package nomad

import (
	"sync"
	"testing"

	msgpackrpc "github.com/hashicorp/net-rpc-msgpackrpc"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/nomad/ci"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/testutil"
)

// TestKeyRingEndpoint_CRUD exercises the basic keyring operations
func TestKeyRingEndpoint_CRUD(t *testing.T) {

	ci.Parallel(t)
	srv, rootToken, shutdown := TestACLServer(t, func(c *Config) {
		c.NumSchedulers = 0 // Prevent automatic dequeue
	})
	defer shutdown()
	testutil.WaitForLeader(t, srv.RPC)
	codec := rpcClient(t, srv)
	id := uuid.Generate()

	// Upsert a new key

	updateReq := &structs.KeyringUpdateRootKeyRequest{
		RootKey: &structs.RootKey{
			Meta: &structs.RootKeyMeta{
				KeyID:     id,
				Algorithm: structs.EncryptionAlgorithmXChaCha20,
				Active:    true,
			},
			Key: []byte{},
		},
		WriteRequest: structs.WriteRequest{Region: "global"},
	}
	var updateResp structs.KeyringUpdateRootKeyResponse
	var err error

	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Update", updateReq, &updateResp)
	require.EqualError(t, err, structs.ErrPermissionDenied.Error())

	updateReq.AuthToken = rootToken.SecretID
	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Update", updateReq, &updateResp)
	require.NoError(t, err)
	require.NotEqual(t, uint64(0), updateResp.Index)

	// Get and List don't need a token here because they rely on mTLS role verification
	getReq := &structs.KeyringGetRootKeyRequest{
		KeyID:        id,
		QueryOptions: structs.QueryOptions{Region: "global"},
	}
	var getResp structs.KeyringGetRootKeyResponse

	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Get", getReq, &getResp)
	require.NoError(t, err)
	require.Equal(t, updateResp.Index, getResp.Index)
	require.Equal(t, structs.EncryptionAlgorithmXChaCha20, getResp.Key.Meta.Algorithm)

	// Make a blocking query for List and wait for an Update

	var wg sync.WaitGroup
	wg.Add(1)
	var listResp structs.KeyringListRootKeyMetaResponse

	go func() {
		defer wg.Done()
		codec := rpcClient(t, srv) // not safe to share across goroutines
		listReq := &structs.KeyringListRootKeyMetaRequest{
			QueryOptions: structs.QueryOptions{
				Region:        "global",
				MinQueryIndex: getResp.Index,
			},
		}
		err = msgpackrpc.CallWithCodec(codec, "KeyRing.List", listReq, &listResp)
		require.NoError(t, err)
	}()

	updateReq.RootKey.Meta.EncryptionsCount++
	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Update", updateReq, &updateResp)
	require.NoError(t, err)
	require.NotEqual(t, uint64(0), updateResp.Index)

	// wait for the blocking query to complete and check the response
	wg.Wait()
	require.Greater(t, listResp.Index, getResp.Index)
	require.Len(t, listResp.Keys, 1)

	// Delete the key and verify that it's gone

	delReq := &structs.KeyringDeleteRootKeyRequest{
		KeyID:        id,
		WriteRequest: structs.WriteRequest{Region: "global"},
	}
	var delResp structs.KeyringDeleteRootKeyResponse

	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Delete", delReq, &delResp)
	require.EqualError(t, err, structs.ErrPermissionDenied.Error())

	delReq.AuthToken = rootToken.SecretID
	err = msgpackrpc.CallWithCodec(codec, "KeyRing.Delete", delReq, &delResp)
	require.NoError(t, err)
	require.Greater(t, delResp.Index, getResp.Index)

	listReq := &structs.KeyringListRootKeyMetaRequest{
		QueryOptions: structs.QueryOptions{Region: "global"},
	}
	err = msgpackrpc.CallWithCodec(codec, "KeyRing.List", listReq, &listResp)
	require.NoError(t, err)
	require.Greater(t, listResp.Index, getResp.Index)
	require.Len(t, listResp.Keys, 0)
}

// TODO
// TestKeyRingEndpoint_Rotate exercises the key rotation logic
func TestKeyRingEndpoint_Rotate(t *testing.T) {
	ci.Parallel(t)
}
