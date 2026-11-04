package install

import (
	ev "clawreef/internal/systembackupevidence"
	"context"
)

// Return the genuine retained original sources to the actual complete Go
// caller. JSON rows/selection/mapping hashes cannot construct these pointers.
// A's PrepareOriginalC1SQLClosure must run on these under its actual SQL tx.
func (p *OriginalC1SigningProduction) OriginalSources(ctx context.Context) ([]*ev.OriginalC1EvidenceSource, error) {
	source, err := p.OriginalSource(ctx)
	if err != nil {
		return nil, err
	}
	sources := []*ev.OriginalC1EvidenceSource{source}
	seen := map[string]bool{}
	for _, ref := range p.run.native.references {
		if seen[ref.Purpose] {
			return nil, ErrInstall
		}
		seen[ref.Purpose] = true
	}
	for _, child := range p.children {
		if child == nil || len(child.children) != 0 || child.run == nil || child.run.parent != p.run.parent {
			return nil, ErrInstall
		}
		actual, err := child.OriginalSource(ctx)
		if err != nil {
			return nil, err
		}
		sources = append(sources, actual)
		for _, ref := range child.run.native.references {
			if seen[ref.Purpose] {
				return nil, ErrInstall
			}
			seen[ref.Purpose] = true
		}
	}
	return sources, nil
}

// Use this method at the full20/final-adoption bridge, never the stage receipt.
// Until all actual native groups have been implemented and committed, it
// refuses instead of manufacturing four missing references or aliasing them.
func (p *OriginalC1SigningProduction) CompleteOriginalSources(ctx context.Context) ([]*ev.OriginalC1EvidenceSource, error) {
	sources, err := p.OriginalSources(ctx)
	if err != nil {
		return nil, err
	}
	actual := map[string]bool{}
	for _, batch := range append([]*OriginalC1SigningProduction{p}, p.children...) {
		for _, ref := range batch.run.native.references {
			actual[ref.Purpose] = true
		}
	}
	if len(actual) != 20 {
		return nil, ErrInstall
	}
	for _, ref := range p.run.parent.request.config.References() {
		if !actual[ref.Purpose] {
			return nil, ErrInstall
		}
	}
	return sources, nil
}

func (n *originalC1NativeObservation) originalNativeSource() BootstrapSourceFilePin {
	if n != nil && n.kind != "signing" {
		return n.groupSource
	}
	if n != nil {
		return n.source
	}
	return BootstrapSourceFilePin{}
}
