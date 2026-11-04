package install

import (
	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	"context"
	"database/sql"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
	"strings"
	"time"
)

// These files select native target data under the ORIGINAL enrolled installer.
// They cannot supply an approved/healthy flag, D handle or publication claim.
// The same process opens the target TLS connection, verifies actual versioning,
// and keeps upstream owner credentials private behind the bounded method gate.
type OriginalC1ChannelInputs struct {
	Store, Credentials                                   BootstrapSourceFilePin
	ControllerDeployment, ControllerPod, OutputDirectory string
}

func sameC1Actor(a, b owner.Binding) bool {
	return a.InstallationID == b.InstallationID && a.Namespace == b.Namespace && a.NamespaceUID == b.NamespaceUID && a.PodName == b.PodName && a.PodUID == b.PodUID && a.ServiceAccountName == b.ServiceAccountName && a.ServiceAccountUID == b.ServiceAccountUID
}
func (p *OriginalC1Production) originalC1JWT(ctx context.Context, actor owner.Binding, audience, name, directory string) (BootstrapSourceFilePin, time.Time, error) {
	var zero BootstrapSourceFilePin
	if !p.live(ctx) || audience == "" || privateDirectory(directory) != nil || filepath.Base(name) != name {
		return zero, time.Time{}, ErrInstall
	}
	i := p.operator.installer
	seconds := int64(600)
	token, err := i.kube.CoreV1().ServiceAccounts(actor.Namespace).CreateToken(ctx, actor.ServiceAccountName, &authn.TokenRequest{Spec: authn.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &seconds, BoundObjectRef: &authn.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: actor.PodName, UID: types.UID(actor.PodUID)}}}, metav1.CreateOptions{})
	if err != nil || token.Status.Token == "" || !token.Status.ExpirationTimestamp.After(time.Now()) {
		return zero, time.Time{}, ErrInstall
	}
	raw, err := originalPublicationToken([]byte(token.Status.Token))
	if err != nil {
		return zero, time.Time{}, ErrInstall
	}
	defer clear(raw)
	review, err := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(raw), Audiences: []string{audience}}}, metav1.CreateOptions{})
	if err != nil || !review.Status.Authenticated || review.Status.User.Username != "system:serviceaccount:"+actor.Namespace+":"+actor.ServiceAccountName || review.Status.User.UID != actor.ServiceAccountUID || len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != audience {
		return zero, time.Time{}, ErrInstall
	}
	if writeNewFiles(directory, map[string][]byte{name: raw}) != nil {
		return zero, time.Time{}, ErrInstall
	}
	return BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(raw)}, token.Status.ExpirationTimestamp.Time, nil
}

// ProduceOriginalC1SigningWithNativeChannel is the concrete original owner
// factory used by the CLI and the enclosing complete adoption invocation.
// Its returned process-local production MUST be retained by the latter; JSON
// selections printed by a stage CLI cannot replace this original source.
func (p *OriginalC1Production) ProduceOriginalC1SigningWithNativeChannel(ctx context.Context, capacityDB *sql.DB, channelIn OriginalC1ChannelInputs, in OriginalC1SigningPipelineInputs, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	if !p.live(ctx) || p.backing != nil || channelIn.ControllerDeployment != in.ControllerDeployment || channelIn.ControllerPod != in.ControllerPod || privateDirectory(channelIn.OutputDirectory) != nil {
		return nil, ErrInstall
	}
	native, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(channelIn.Store, 262144)
	var store ev.S3Config
	if err != nil || decodeExact(raw, &store) != nil || store.Identity != p.channel.Store.Identity || store.Version != p.channel.Store.Version || store.Root != p.channel.Root || store.Installation != string(p.domain.Scope.Installation) {
		return nil, ErrInstall
	}
	raw, err = readBootstrapSourcePin(channelIn.Credentials, 16384)
	var credentials struct{ AccessKey, SecretKey string }
	if err != nil || decodeExact(raw, &credentials) != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	audience := "clawreef-original-c1-sts-" + p.operator.installer.planHash[:20]
	channel, err := ev.NewOriginalC1OwnerChannel(ctx, ev.OriginalC1ChannelOwner{Upstream: store, AccessKey: []byte(credentials.AccessKey), SecretKey: []byte(credentials.SecretKey), Kubernetes: p.operator.installer.kube, Namespace: native.actor.Namespace, NamespaceUID: native.actor.NamespaceUID, PodName: native.actor.PodName, PodUID: native.actor.PodUID, ServiceAccount: native.actor.ServiceAccountName, ServiceAccountUID: native.actor.ServiceAccountUID, Issuer: native.signing.Trust.Issuer, Audience: audience, RoleARN: "arn:aws:iam::000000000000:role/original-c1-owner"})
	credentials.AccessKey = ""
	credentials.SecretKey = ""
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			channel.Close()
		}
	}()
	if _, err = p.BindOriginalC1BackingStore(ctx, channel.BackingStoreSource(), issuerPrivate); err != nil {
		return nil, err
	}
	in.STSJWT, _, err = p.originalC1JWT(ctx, native.actor, audience, "c1-sts.jwt", channelIn.OutputDirectory)
	if err != nil {
		return nil, err
	}
	in.AuthenticationAudience = "clawreef-original-c1-auth-" + p.operator.installer.planHash[:20]
	in.AuthenticationJWT, _, err = p.originalC1JWT(ctx, native.actor, in.AuthenticationAudience, "c1-authentication.jwt", channelIn.OutputDirectory)
	if err != nil {
		return nil, err
	}
	current, err := p.operator.installer.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPod)
	if err != nil || !sameC1Actor(current, native.actor) || strings.EqualFold(in.STSJWT.File, in.AuthenticationJWT.File) {
		return nil, ErrInstall
	}
	batch, err := p.ProduceOriginalC1Signing(ctx, capacityDB, channel, in, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	batch.channel = channel
	ok = true
	return batch, nil
}
