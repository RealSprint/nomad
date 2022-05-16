package nomad

import (
	"fmt"
	"time"

	metrics "github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	memdb "github.com/hashicorp/go-memdb"

	"github.com/hashicorp/nomad/nomad/state"
	"github.com/hashicorp/nomad/nomad/structs"
)

// KeyRing endpoint serves RPCs for secure variables key management
type KeyRing struct {
	srv       *Server
	logger    hclog.Logger
	encrypter *Encrypter
	ctx       *RPCContext // context for connection, to check TLS role
}

func (k *KeyRing) Rotate(args *structs.KeyringRotateRootKeyRequest, reply *structs.KeyringRotateRootKeyResponse) error {
	if done, err := k.srv.forward("KeyRing.Rotate", args, args, reply); done {
		return err
	}

	defer metrics.MeasureSince([]string{"nomad", "keyring", "rotate"}, time.Now())

	if aclObj, err := k.srv.ResolveToken(args.AuthToken); err != nil {
		return err
	} else if aclObj != nil && !aclObj.IsManagement() {
		return structs.ErrPermissionDenied
	}

	if args.Full {
		// TODO: implement full key rotation via a core job
	}

	meta := structs.NewRootKeyMeta()
	meta.Algorithm = structs.EncryptionAlgorithmXChaCha20 // TODO: set this from server config
	meta.Active = true

	// TODO: have the Encrypter generate and persist the actual key
	// material. this is just here to silence the structcheck lint
	for keyID := range k.encrypter.ciphers {
		k.logger.Trace("TODO", "key", keyID)
	}

	// Update metadata via Raft so followers can retrieve this key
	req := structs.KeyringUpdateRootKeyMetaRequest{
		RootKeyMeta:  meta,
		WriteRequest: args.WriteRequest,
	}
	out, index, err := k.srv.raftApply(structs.RootKeyMetaUpsertRequestType, req)
	if err != nil {
		return err
	}
	if err, ok := out.(error); ok && err != nil {
		return err
	}
	reply.Index = index
	return nil
}

func (k *KeyRing) List(args *structs.KeyringListRootKeyMetaRequest, reply *structs.KeyringListRootKeyMetaResponse) error {
	if done, err := k.srv.forward("KeyRing.List", args, args, reply); done {
		return err
	}

	defer metrics.MeasureSince([]string{"nomad", "keyring", "list"}, time.Now())

	// we need to allow both humans with management tokens and
	// non-leader servers to list keys, in order to support
	// replication
	err := validateTLSCertificateLevel(k.srv, k.ctx, tlsCertificateLevelServer)
	if err != nil {
		if aclObj, err := k.srv.ResolveToken(args.AuthToken); err != nil {
			return err
		} else if aclObj != nil && !aclObj.IsManagement() {
			return structs.ErrPermissionDenied
		}
	}

	// Setup the blocking query
	opts := blockingOptions{
		queryOpts: &args.QueryOptions,
		queryMeta: &reply.QueryMeta,
		run: func(ws memdb.WatchSet, s *state.StateStore) error {

			// retrieve all the key metadata
			snap, err := k.srv.fsm.State().Snapshot()
			if err != nil {
				return err
			}
			iter, err := snap.RootKeyMetas(ws)
			if err != nil {
				return err
			}

			for {
				raw := iter.Next()
				if raw == nil {
					break
				}
				keyMeta := raw.(*structs.RootKeyMeta)
				reply.Keys = append(reply.Keys, keyMeta)
			}
			return k.srv.replySetIndex(state.TableRootKeyMeta, &reply.QueryMeta)
		},
	}
	return k.srv.blockingRPC(&opts)
}

// Update updates an existing key in the keyring, including both the
// key material and metadata.
func (k *KeyRing) Update(args *structs.KeyringUpdateRootKeyRequest, reply *structs.KeyringUpdateRootKeyResponse) error {
	if done, err := k.srv.forward("KeyRing.Update", args, args, reply); done {
		return err
	}

	defer metrics.MeasureSince([]string{"nomad", "keyring", "update"}, time.Now())

	if aclObj, err := k.srv.ResolveToken(args.AuthToken); err != nil {
		return err
	} else if aclObj != nil && !aclObj.IsManagement() {
		return structs.ErrPermissionDenied
	}

	// TODO: wind this all up in a Validate method?
	if args.RootKey.Meta == nil {
		return fmt.Errorf("root key metadata is required")
	}
	if args.RootKey.Meta.KeyID == "" {
		return fmt.Errorf("root key ID is required")
	}

	// lookup any existing key and validate the update
	snap, err := k.srv.fsm.State().Snapshot()
	if err != nil {
		return err
	}
	ws := memdb.NewWatchSet()
	keyMeta, err := snap.RootKeyMetaByID(ws, args.RootKey.Meta.KeyID)
	if err != nil {
		return err
	}
	if keyMeta != nil && keyMeta.Algorithm != args.RootKey.Meta.Algorithm {
		return fmt.Errorf("root key algorithm cannot be changed after a key is created")
	}

	// unwrap the request to turn it into a meta update only
	metaReq := &structs.KeyringUpdateRootKeyMetaRequest{
		RootKeyMeta:  args.RootKey.Meta,
		WriteRequest: args.WriteRequest,
	}

	// Update via Raft
	out, index, err := k.srv.raftApply(structs.RootKeyMetaUpsertRequestType, metaReq)
	if err != nil {
		return err
	}
	if err, ok := out.(error); ok && err != nil {
		return err
	}
	reply.Index = index
	return nil
}

// Get retrieves an existing key from the keyring, including both the
// key material and metadata. It is used only for replication.
func (k *KeyRing) Get(args *structs.KeyringGetRootKeyRequest, reply *structs.KeyringGetRootKeyResponse) error {
	// ensure that only another server can make this request
	err := validateTLSCertificateLevel(k.srv, k.ctx, tlsCertificateLevelServer)
	if err != nil {
		return err
	}

	if done, err := k.srv.forward("KeyRing.Get", args, args, reply); done {
		return err
	}

	defer metrics.MeasureSince([]string{"nomad", "keyring", "get"}, time.Now())

	// Setup the blocking query
	opts := blockingOptions{
		queryOpts: &args.QueryOptions,
		queryMeta: &reply.QueryMeta,
		run: func(ws memdb.WatchSet, s *state.StateStore) error {

			// retrieve the key metadata
			snap, err := k.srv.fsm.State().Snapshot()
			if err != nil {
				return err
			}
			keyMeta, err := snap.RootKeyMetaByID(ws, args.KeyID)
			if err != nil {
				return err
			}

			// TODO: retrieve the key material from the keyring
			key := &structs.RootKey{
				Meta: keyMeta,
				Key:  []byte{},
			}
			reply.Key = key

			// TODO: should this be the table index or the ModifyIndex?
			// return k.srv.replySetIndex(state.TableRootKeyMeta, &reply.QueryMeta)
			reply.Index = keyMeta.ModifyIndex
			return nil
		},
	}
	return k.srv.blockingRPC(&opts)
}

func (k *KeyRing) Delete(args *structs.KeyringDeleteRootKeyRequest, reply *structs.KeyringDeleteRootKeyResponse) error {
	if done, err := k.srv.forward("KeyRing.Delete", args, args, reply); done {
		return err
	}

	defer metrics.MeasureSince([]string{"nomad", "keyring", "delete"}, time.Now())

	if aclObj, err := k.srv.ResolveToken(args.AuthToken); err != nil {
		return err
	} else if aclObj != nil && !aclObj.IsManagement() {
		return structs.ErrPermissionDenied
	}

	// Update via Raft
	out, index, err := k.srv.raftApply(structs.RootKeyMetaDeleteRequestType, args)
	if err != nil {
		return err
	}
	if err, ok := out.(error); ok && err != nil {
		return err
	}
	reply.Index = index
	return nil
}
