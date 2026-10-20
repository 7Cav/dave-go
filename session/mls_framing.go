package session

import (
	"encoding/binary"
	"fmt"

	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// RFC 9420 code points the framing walk needs and mls-go has no constants for.
const (
	leafNodeSourceKeyPackage = 1 // §7.2
	leafNodeSourceUpdate     = 2
	leafNodeSourceCommit     = 3
	pskTypeExternal          = 1 // §8.4
	pskTypeResumption        = 2
	lifetimeSize             = 16 // §7.2: uint64 not_before, uint64 not_after
)

// splitMLSMessages splits the MLSMessage vector of an append op 27 into its
// messages, each the gateway's bytes as sent. mls-go's parser reads a message
// to the end of the buffer it gets, so the session finds where each message
// ends itself, by stepping over every field by the length RFC 9420 gives it.
// It fails on a message it can't step to the end of: one cut short, bytes
// after the last message that aren't a whole message, or a field whose type
// RFC 9420 gives no layout for.
func splitMLSMessages(vec []byte) ([][]byte, error) {
	var msgs [][]byte
	for len(vec) > 0 {
		r := wireReader{buf: vec}
		r.mlsMessage()
		if r.err != nil {
			return nil, fmt.Errorf("message %d in the vector: %w", len(msgs), r.err)
		}
		msgs = append(msgs, vec[:r.pos:r.pos])
		vec = vec[r.pos:]
	}

	return msgs, nil
}

// wireReader steps over RFC 9420 structures in buf. The first failure sticks
// and turns every later step into a no-op, so a walk checks err once at the
// end. It never reads past the end of buf.
type wireReader struct {
	buf []byte
	pos int
	err error
}

// fail records a field whose value RFC 9420 gives no layout for. what names
// the field and its value.
func (r *wireReader) fail(what string) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s at offset %d", errMalformedMessage, what, r.pos)
	}
}

func (r *wireReader) skip(n int) {
	if r.err != nil {
		return
	}
	if n > len(r.buf)-r.pos {
		r.err = fmt.Errorf("%w: a %d-byte field at offset %d runs past the %d bytes left",
			ErrProposalTooShort, n, r.pos, len(r.buf)-r.pos)

		return
	}
	r.pos += n
}

func (r *wireReader) u8() uint8 {
	start := r.pos
	r.skip(1)
	if r.err != nil {
		return 0
	}

	return r.buf[start]
}

func (r *wireReader) u16() uint16 {
	start := r.pos
	r.skip(2)
	if r.err != nil {
		return 0
	}

	return binary.BigEndian.Uint16(r.buf[start:])
}

// vec steps over a variable-length vector, opaque<V> included.
func (r *wireReader) vec() {
	if r.err != nil {
		return
	}
	n, size, err := readTLSVectorLength(r.buf[r.pos:])
	if err != nil {
		r.err = fmt.Errorf("vector length at offset %d: %w", r.pos, err)

		return
	}
	r.pos += size
	r.skip(int(n))
}

// mlsMessage steps over an MLSMessage (§6). RFC 9420 gives a layout only for
// version mls10.
func (r *wireReader) mlsMessage() {
	if v := keypackages.ProtocolVersion(r.u16()); v != keypackages.MLS10 {
		r.fail(fmt.Sprintf("protocol version %d", v))
	}
	switch wf := framing.WireFormat(r.u16()); wf {
	case framing.WireFormatPublicMessage:
		r.publicMessage()
	case framing.WireFormatPrivateMessage:
		r.vec()   // group_id
		r.skip(8) // epoch
		r.skip(1) // content_type
		r.vec()   // authenticated_data
		r.vec()   // encrypted_sender_data
		r.vec()   // ciphertext
	case framing.WireFormatWelcome:
		r.skip(2) // cipher_suite
		r.vec()   // secrets
		r.vec()   // encrypted_group_info
	case framing.WireFormatGroupInfo:
		r.groupInfo()
	case framing.WireFormatKeyPackage:
		r.keyPackage()
	default:
		r.fail(fmt.Sprintf("wire format %d", wf))
	}
}

// publicMessage steps over a PublicMessage after its wire format (§6.2).
func (r *wireReader) publicMessage() {
	r.vec()   // group_id
	r.skip(8) // epoch
	sender := framing.SenderType(r.u8())
	switch sender {
	case framing.SenderTypeMember, framing.SenderTypeExternal:
		r.skip(4) // leaf_index or sender_index
	case framing.SenderTypeNewMemberProposal, framing.SenderTypeNewMemberCommit:
	default:
		r.fail(fmt.Sprintf("sender type %d", sender))
	}
	r.vec() // authenticated_data
	content := framing.ContentType(r.u8())
	switch content {
	case framing.ContentTypeApplication:
		r.vec() // application_data
	case framing.ContentTypeProposal:
		r.proposal()
	case framing.ContentTypeCommit:
		r.commit()
	default:
		r.fail(fmt.Sprintf("content type %d", content))
	}
	r.vec() // signature
	if content == framing.ContentTypeCommit {
		r.vec() // confirmation_tag
	}
	if sender == framing.SenderTypeMember {
		r.vec() // membership_tag
	}
}

// proposal steps over a Proposal (§12.1).
func (r *wireReader) proposal() {
	switch pt := group.ProposalType(r.u16()); pt {
	case group.ProposalTypeAdd:
		r.keyPackage()
	case group.ProposalTypeUpdate:
		r.leafNode()
	case group.ProposalTypeRemove:
		r.skip(4) // removed
	case group.ProposalTypePreSharedKey:
		r.preSharedKeyID()
	case group.ProposalTypeReInit:
		r.vec()   // group_id
		r.skip(4) // version, cipher_suite
		r.vec()   // extensions
	case group.ProposalTypeExternalInit:
		r.vec() // kem_output
	case group.ProposalTypeGroupContextExtensions:
		r.vec() // extensions
	default:
		r.fail(fmt.Sprintf("proposal type %d", pt))
	}
}

// preSharedKeyID steps over a PreSharedKeyID (§8.4).
func (r *wireReader) preSharedKeyID() {
	switch pskType := r.u8(); pskType {
	case pskTypeExternal:
		r.vec() // psk_id
	case pskTypeResumption:
		r.skip(1) // usage
		r.vec()   // psk_group_id
		r.skip(8) // psk_epoch
	default:
		r.fail(fmt.Sprintf("psk type %d", pskType))
	}
	r.vec() // psk_nonce
}

// commit steps over a Commit (§12.4).
func (r *wireReader) commit() {
	r.vec() // proposals
	switch present := r.u8(); present {
	case 0:
	case 1:
		r.leafNode() // UpdatePath.leaf_node
		r.vec()      // UpdatePath.nodes
	default:
		r.fail(fmt.Sprintf("optional<UpdatePath> flag %d", present))
	}
}

// keyPackage steps over a KeyPackage (§10).
func (r *wireReader) keyPackage() {
	r.skip(4) // version, cipher_suite
	r.vec()   // init_key
	r.leafNode()
	r.vec() // extensions
	r.vec() // signature
}

// leafNode steps over a LeafNode (§7.2).
func (r *wireReader) leafNode() {
	r.vec() // encryption_key
	r.vec() // signature_key
	switch ct := credentials.CredentialType(r.u16()); ct {
	case credentials.BasicCredential:
		r.vec() // identity
	case credentials.X509Credential:
		r.vec() // certificates
	default:
		r.fail(fmt.Sprintf("credential type %d", ct))
	}
	for range 5 { // capabilities: versions, cipher_suites, extensions, proposals, credentials
		r.vec()
	}
	switch source := r.u8(); source {
	case leafNodeSourceKeyPackage:
		r.skip(lifetimeSize)
	case leafNodeSourceUpdate:
	case leafNodeSourceCommit:
		r.vec() // parent_hash
	default:
		r.fail(fmt.Sprintf("leaf node source %d", source))
	}
	r.vec() // extensions
	r.vec() // signature
}

// groupInfo steps over a GroupInfo (§12.4.3).
func (r *wireReader) groupInfo() {
	r.skip(4) // GroupContext.version, cipher_suite
	r.vec()   // group_id
	r.skip(8) // epoch
	r.vec()   // tree_hash
	r.vec()   // confirmed_transcript_hash
	r.vec()   // GroupContext.extensions
	r.vec()   // extensions
	r.vec()   // confirmation_tag
	r.skip(4) // signer
	r.vec()   // signature
}
