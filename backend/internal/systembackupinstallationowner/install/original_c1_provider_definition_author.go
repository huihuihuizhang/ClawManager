package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	probe "clawreef/internal/systembackupreferenceprobe"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"time"
)

type OriginalC1ChannelMaterialSelection struct {
	Version          string
	Store            ev.S3Config
	Write            ev.KeyRef
	Credentials      BootstrapSourceFilePin
	NotBefore, Until time.Time
}

type OriginalC1ProviderDefinitionInputs struct {
	ChannelMaterial                                                                                                                      BootstrapSourceFilePin
	ChannelPrincipal                                                                                                                     probe.Principal
	ChannelCredentials                                                                                                                   BootstrapSourceFilePin
	Version, ArchiveMaterialDirectory, ControllerDeployment, ControllerPod, RelayService, RelayContainer, RelayEndpoint, OutputDirectory string
	Config, Deployment, S3Profile, VaultCA, RelayCA, RelayCertificate, RelayPrivateKey                                                   BootstrapSourceFilePin
}
type OriginalC1ProviderDefinitionReceipt struct {
	Version, State                                string
	Six, StatusRelay, Channel, Store, Credentials BootstrapSourceFilePin
	StatusRelayReference                          sec.BootstrapSecretRef
	SixReferences                                 []sec.BootstrapSecretRef
	Until                                         time.Time
}

// Locations/configuration DATA only. All identities are obtained from real
// Kube ownership and native S3/Vault/mTLS reads. This does not grant capture or
// sign a reference; actual C1 owners will independently observe again.
func (i *Installer) PrepareOriginalC1ProviderDefinitions(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalC1ProviderDefinitionInputs) (OriginalC1ProviderDefinitionReceipt, error) {
	var zero OriginalC1ProviderDefinitionReceipt
	if i == nil || ctx == nil || in.Version != "original-c1-provider-definition-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	archive, e := i.QueryOriginalArchiveEvidenceMaterial(ctx, password, enrollment, in.ArchiveMaterialDirectory)
	if e != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(in.S3Profile, 262144)
	var s3 probe.S3Profile
	if e != nil || decodeExact(raw, &s3) != nil || probe.ValidateS3Profile(s3) != nil {
		return zero, ErrInstall
	}
	// Native owner outputs precede final Config/Request signing. Derive the
	// six locator identities from the exact observed original principals/key,
	// avoiding a Config -> StatusRelay -> Config bootstrap cycle. These are
	// selection DATA; observeSixReference still performs native checks below.
	refs := []sec.BootstrapSecretRef{{Purpose: "evidence_store", IdentityHash: s3.Evidence.Identity, Version: s3.Evidence.Version}, {Purpose: "evidence_kek", IdentityHash: archive.Vault.Transit.Key.Identity, Version: archive.Vault.Transit.Key.Version}}
	for _, principal := range s3.Principals {
		refs = append(refs, sec.BootstrapSecretRef{Purpose: principal.Purpose, IdentityHash: principal.AccountSHA256, Version: principal.PolicyName})
	}
	sort.Slice(refs, func(a, b int) bool { return refs[a].Purpose < refs[b].Purpose })
	if !sameSixReferences(refs, refs) {
		return zero, ErrInstall
	}
	if in.Config != (BootstrapSourceFilePin{}) {
		configRaw, err := readBootstrapSourcePin(in.Config, 1<<20)
		if err != nil {
			return zero, ErrInstall
		}
		config, err := sec.DecodeBootstrapConfig(configRaw)
		if err != nil {
			return zero, ErrInstall
		}
		selected, err := sixConfigReferences(config)
		if err != nil || !sameSixReferences(selected, refs) {
			return zero, ErrInstall
		}
	}
	until := minTime(archive.Until, op.until)
	six := SixReferenceDefinition{Version: SixReferenceVersion, References: refs, Deployment: in.Deployment, S3: s3, Vault: archive.Vault, VaultCA: in.VaultCA, NotBefore: now, Until: until}
	if _, e = observeSixReference(ctx, i.kube, i.plan.Target, six); e != nil {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPod)
	if e != nil {
		return zero, ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(i.plan.Target.Namespace).Get(ctx, in.ControllerPod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != actor.PodUID || len(pod.OwnerReferences) != 1 {
		return zero, ErrInstall
	}
	dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, in.ControllerDeployment, metav1.GetOptions{})
	if e != nil {
		return zero, ErrInstall
	}
	rs, e := i.kube.AppsV1().ReplicaSets(i.plan.Target.Namespace).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if e != nil {
		return zero, ErrInstall
	}
	sa, e := i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Get(ctx, actor.ServiceAccountName, metav1.GetOptions{})
	if e != nil || string(sa.UID) != actor.ServiceAccountUID {
		return zero, ErrInstall
	}
	svc, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, in.RelayService, metav1.GetOptions{})
	if e != nil {
		return zero, ErrInstall
	}
	spec, e := json.Marshal(pod.Spec)
	if e != nil {
		return zero, ErrInstall
	}
	image := ""
	for _, st := range pod.Status.ContainerStatuses {
		if st.Name == in.RelayContainer && st.Ready && st.State.Running != nil && st.ContainerID != "" {
			if image != "" {
				return zero, ErrInstall
			}
			image = st.ImageID
		}
	}
	if image == "" {
		return zero, ErrInstall
	}
	controller := BootstrapSourceController{Namespace: actor.Namespace, NamespaceUID: actor.NamespaceUID, Deployment: dep.Name, DeploymentUID: string(dep.UID), ReplicaSet: rs.Name, ReplicaSetUID: string(rs.UID), Pod: pod.Name, PodUID: string(pod.UID), ServiceAccount: sa.Name, ServiceAccountUID: string(sa.UID)}
	ca, e := readBootstrapSourcePin(in.RelayCA, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	cert, e := readBootstrapSourcePin(in.RelayCertificate, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	key, e := readBootstrapSourcePin(in.RelayPrivateKey, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return zero, ErrInstall
	}
	clientLeaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return zero, ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return zero, ErrInstall
	}
	u, e := url.Parse(in.RelayEndpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return zero, ErrInstall
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), Certificates: []tls.Certificate{pair}}}
	c, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return zero, ErrInstall
	}
	actual, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return zero, ErrInstall
	}
	native := actual.ConnectionState()
	c.Close()
	if !native.HandshakeComplete || native.Version != tls.VersionTLS13 || len(native.VerifiedChains) == 0 || len(native.PeerCertificates) == 0 {
		return zero, ErrInstall
	}
	server := native.PeerCertificates[0]
	spki, e := x509.MarshalPKIXPublicKey(server.PublicKey)
	if e != nil {
		return zero, ErrInstall
	}
	until = minTime(until, minTime(clientLeaf.NotAfter, server.NotAfter))
	relay := StatusRelayReferenceDefinition{Version: StatusRelayReferenceVersion, ReferenceVersion: "relay-" + hash(append(spec, cert...))[:24], Deployment: in.Deployment, Controller: controller, Service: svc.Name, ServiceUID: string(svc.UID), Endpoint: in.RelayEndpoint, Container: in.RelayContainer, ContainerImageID: image, PodSpecSHA256: hash(spec), CA: in.RelayCA, ClientCertificate: in.RelayCertificate, ClientPrivateKey: in.RelayPrivateKey, ServerLeafSHA256: hash(server.Raw), ServerSPKISHA256: hash(spki), NotBefore: now, Until: until}
	if _, e = observeStatusRelayReference(ctx, i.kube, i.plan.Target, relay); e != nil {
		return zero, ErrInstall
	}
	// This is the independent native A owner channel principal, never generic
	// evidence_write (PUT only), metadata observer or MinIO root credentials.
	for _, p := range append([]probe.Principal{s3.Observer}, s3.Principals...) {
		if p.Credential.File == in.ChannelCredentials.File || p.Credential.SHA256 == in.ChannelCredentials.SHA256 {
			return zero, ErrInstall
		}
	}
	credRaw, e := readBootstrapSourcePin(in.ChannelCredentials, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(credRaw)
	// Native named/effective policy and deny-admin observation authenticates
	// this separate upstream purpose before converting its retained credentials.
	if probe.ObserveOriginalS3Channel(ctx, s3, in.ChannelPrincipal) != nil {
		return zero, ErrInstall
	}
	lowerRaw, e := probe.ReadPinned(in.ChannelPrincipal.Credential, 16384)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(lowerRaw)
	expected, e := probe.OriginalS3ChannelCredentials(lowerRaw)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(expected)
	if !bytes.Equal(expected, credRaw) {
		return zero, ErrInstall
	}
	var credential struct{ AccessKey, SecretKey string }
	if decodeExact(credRaw, &credential) != nil || credential.AccessKey == "" || credential.SecretKey == "" {
		return zero, ErrInstall
	}
	selectionRaw, e := readBootstrapSourcePin(in.ChannelMaterial, 262144)
	var channelMaterial OriginalC1ChannelMaterialSelection
	if e != nil || decodeExact(selectionRaw, &channelMaterial) != nil || channelMaterial.Version != "original-c1-channel-native-material.v1" || channelMaterial.Credentials != in.ChannelCredentials || now.Before(channelMaterial.NotBefore) || !now.Before(channelMaterial.Until) {
		return zero, ErrInstall
	}
	// Reconstruct only DATA with A's exact real owner helper. Together with
	// ObserveOriginalS3Channel above, this binds actual native principal/ACL,
	// both credential encodings, Store, purpose/key identity and original epoch.
	expectedSelection, e := originalC1S3ChannelSelection(s3, in.ChannelPrincipal, in.ChannelCredentials, channelMaterial.Until)
	if e != nil || !bytes.Equal(expectedSelection, selectionRaw) {
		return zero, ErrInstall
	}
	until = minTime(until, channelMaterial.Until)
	six.Until = until
	relay.Until = until
	// Exact original native material, no fabricated recovery or success flag.
	recovery, e := canonical(struct {
		Profile  probe.S3Profile
		VaultKey ev.KeyRef
	}{s3, archive.Vault.Transit.Key})
	if e != nil {
		return zero, ErrInstall
	}
	channel := ev.ProducerEvidenceChannel{Root: s3.Evidence.Root, Store: ev.KeyRef{Identity: s3.Evidence.Identity, Version: s3.Evidence.Version}, Write: channelMaterial.Write, RecoveryProfileHash: hash(recovery)}
	sixRaw, e := canonical(six)
	if e != nil {
		return zero, ErrInstall
	}
	relayRaw, e := canonical(relay)
	if e != nil {
		return zero, ErrInstall
	}
	relayRef, e := StatusRelayReferenceIdentity(relayRaw, hash(relayRaw))
	if e != nil {
		return zero, ErrInstall
	}
	channelRaw, e := canonical(channel)
	if e != nil {
		return zero, ErrInstall
	}
	storeRaw, e := canonical(s3.Evidence)
	if e != nil {
		return zero, ErrInstall
	}
	credentialsRaw, e := canonical(struct{ AccessKey, SecretKey string }{credential.AccessKey, credential.SecretKey})
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(credentialsRaw)
	current, _, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || current.cas != state.cas || op.authority(ctx, enrollment) != nil || !time.Now().Before(until) || observeBootstrapSourceController(ctx, i.kube, i.plan.Target, controller) != nil || recheckSixReferenceFiles(six) != nil {
		return zero, ErrInstall
	}
	for _, p := range []BootstrapSourceFilePin{in.ChannelMaterial, in.ChannelCredentials, {File: in.ChannelPrincipal.Credential.File, SHA256: in.ChannelPrincipal.Credential.SHA256}} {
		b, e := readBootstrapSourcePin(p, 262144)
		clear(b)
		if e != nil {
			return zero, ErrInstall
		}
	}
	files := map[string][]byte{"six.definition.json": sixRaw, "status-relay.definition.json": relayRaw, "channel.json": channelRaw, "store.json": storeRaw, "channel-credentials.private.json": credentialsRaw}
	if writeNewFiles(in.OutputDirectory, files) != nil {
		return zero, ErrInstall
	}
	pin := func(name string) BootstrapSourceFilePin {
		return BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, name), SHA256: hash(files[name])}
	}
	for name, want := range files {
		got, e := readBootstrapSourcePin(pin(name), 262144)
		if e != nil || hash(got) != hash(want) {
			return zero, ErrInstall
		}
		clear(got)
	}
	return OriginalC1ProviderDefinitionReceipt{Version: "original-c1-provider-definition-result.v1", State: "original_native_definitions_authored_not_signed_or_adopted", Six: pin("six.definition.json"), StatusRelay: pin("status-relay.definition.json"), Channel: pin("channel.json"), Store: pin("store.json"), Credentials: pin("channel-credentials.private.json"), StatusRelayReference: relayRef, SixReferences: refs, Until: until}, nil
}
