package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"
    "os"
    "path/filepath"

    "clawreef/internal/config"
)

type originalSourceConfigFile struct { Path,Resolved,SHA256 string; Missing bool }

func originalSourceConfigFiles() ([]originalSourceConfigFile,error) {
    out:=[]originalSourceConfigFile{}
    for _,name:=range []string{"configs/k8s.yaml","backend/configs/k8s.yaml","../configs/k8s.yaml","/app/configs/k8s.yaml","configs/dev.yaml","backend/configs/dev.yaml"} {
        absolute,e:=filepath.Abs(name);if e!=nil{return nil,e}
        item:=originalSourceConfigFile{Path:absolute}
        actual,e:=filepath.EvalSymlinks(absolute)
        if os.IsNotExist(e) {item.Missing=true;out=append(out,item);continue}
        if e!=nil{return nil,e};item.Resolved=actual
        f,e:=os.Open(absolute);if e!=nil{return nil,e}
        info,e:=f.Stat();if e!=nil || !info.Mode().IsRegular() || info.Size()>1<<20 {f.Close();return nil,os.ErrInvalid}
        raw,e:=io.ReadAll(io.LimitReader(f,1<<20+1));closeErr:=f.Close()
        if e!=nil || closeErr!=nil || len(raw)>1<<20 {clear(raw);return nil,os.ErrInvalid}
        sum:=sha256.Sum256(raw);clear(raw);item.SHA256=hex.EncodeToString(sum[:]);out=append(out,item)
    }
    return out,nil
}

// Local read-only mode in the SAME installed server executable/container. It
// uses the actual production config.Load YAML/env precedence. It opens no DB,
// listener, signer or task. Only the explicit non-secret coordinate whitelist
// below leaves this process; all absent/selected config paths are pinned twice.
func runOriginalSourceConfigData(out io.Writer) int {
    if out==nil{return 2}
    before,e:=originalSourceConfigFiles();if e!=nil{return 1}
    cfg,e:=config.Load();if e!=nil{return 1}
    after,e:=originalSourceConfigFiles();if e!=nil{return 1}
    a,e:=json.Marshal(before);if e!=nil{return 1};b,e:=json.Marshal(after);if e!=nil || !bytes.Equal(a,b){return 1}
    value:=struct {
        Version string
        WorkspaceRoot,ObjectBucket,ObjectPrefix string
        Files []originalSourceConfigFile
        RuntimeQualified,BackupReady bool
    }{Version:"original-application-config-coordinates.v1",WorkspaceRoot:cfg.Runtime.WorkspaceRoot,ObjectBucket:cfg.ObjectStorage.Bucket,ObjectPrefix:cfg.ObjectStorage.BasePath,Files:after}
    if json.NewEncoder(out).Encode(value)!=nil{return 3};return 0
}
