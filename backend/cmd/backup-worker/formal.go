package main

import (
	"clawreef/internal/systembackup/worker"
	"context"
	"encoding/json"
	"io"
	"os"
)

// Shared by the actual Linux CLI after authenticated Ready. Tests exercise
// this same formal route on Windows without changing the platform guard.
func runFormalInvocation(ctx context.Context, i worker.Invocation, control *worker.ControlClient, formalConfig string, store *os.Root, stdout io.Writer) error {
	hash, err := i.Hash()
	if err != nil || control == nil || store == nil || !worker.ValidateControl(worker.ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "ready"}) {
		return worker.ErrRequest
	}
	// Provider-backed work NEVER reaches functional Acquire/Complete or
	// receives Lease.DEK. The original control path reserves key use in Job.
	materials, err := worker.LoadFormalCaptureMaterials(formalConfig, i)
	if err != nil {
		return err
	}
	var job *worker.CaptureKeyJob
	if materials.PermitDelivery != nil {
		job, err = worker.NewDeliveredCaptureKeyJob(ctx, control, i, materials.KMS, *materials.PermitDelivery)
	} else {
		job, err = worker.NewCaptureKeyJob(ctx, control, i, materials.KMS, materials.Permit)
	}
	if err != nil {
		return err
	}
	defer job.Close()
	env := worker.FormalCaptureEnvironment{Staging: store}
	if i.Request.SourceRedis != nil || i.Request.Teams != nil || i.Request.Database != nil || i.Request.SkillObjects != nil {
		sources, err := worker.OpenFormalCaptureSources(ctx, i, job, materials.Sources)
		if err != nil {
			return err
		}
		defer sources.Close()
		env.Database, env.Teams, env.SourceRedis = sources.Database, sources.Teams, sources.SourceRedis
		env.SourceAuthorize, env.SourceValidUntil = sources.Authorize, sources.ValidUntil()
		if i.Request.SkillObjects != nil {
			env.SkillObjects, err = sources.SkillObjects()
			if err != nil {
				return err
			}
		}
	} else if i.Request.Resources != nil {
		env.Resources, err = worker.OpenResourceCaptureSources(ctx, i, materials.Resources)
		if err != nil {
			return err
		}
		defer env.Resources.Close()
	} else {
		workspace, err := os.OpenRoot(i.WorkspacePath)
		if err != nil {
			return worker.ErrRequest
		}
		defer workspace.Close()
		env.Workspace = workspace
	}
	result, err := worker.RunFormalCapture(ctx, i, job, env)
	if err != nil {
		return err
	}
	if err = job.ReportCandidate(ctx, i, result); err != nil {
		return err
	}
	// Durable candidate ACK is not a completed module, artifact or acceptance.
	// The independent formal observer/finalizer consumes this original report.
	return json.NewEncoder(stdout).Encode(result)
}
