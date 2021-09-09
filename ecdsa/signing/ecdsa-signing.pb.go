// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: ecdsa-signing.proto

package signing

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

//
// Represents a P2P message sent to each party during Round 1 of the ECDSA TSS signing protocol.
type SignRound1Message1 struct {
	C                    []byte   `protobuf:"bytes,1,opt,name=c,proto3" json:"c,omitempty"`
	RangeProofAlice      [][]byte `protobuf:"bytes,2,rep,name=range_proof_alice,json=rangeProofAlice,proto3" json:"range_proof_alice,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound1Message1) Reset()         { *m = SignRound1Message1{} }
func (m *SignRound1Message1) String() string { return proto.CompactTextString(m) }
func (*SignRound1Message1) ProtoMessage()    {}
func (*SignRound1Message1) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{0}
}

func (m *SignRound1Message1) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound1Message1.Unmarshal(m, b)
}
func (m *SignRound1Message1) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound1Message1.Marshal(b, m, deterministic)
}
func (m *SignRound1Message1) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound1Message1.Merge(m, src)
}
func (m *SignRound1Message1) XXX_Size() int {
	return xxx_messageInfo_SignRound1Message1.Size(m)
}
func (m *SignRound1Message1) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound1Message1.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound1Message1 proto.InternalMessageInfo

func (m *SignRound1Message1) GetC() []byte {
	if m != nil {
		return m.C
	}
	return nil
}

func (m *SignRound1Message1) GetRangeProofAlice() [][]byte {
	if m != nil {
		return m.RangeProofAlice
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 1 of the ECDSA TSS signing protocol.
type SignRound1Message2 struct {
	Commitment           []byte   `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound1Message2) Reset()         { *m = SignRound1Message2{} }
func (m *SignRound1Message2) String() string { return proto.CompactTextString(m) }
func (*SignRound1Message2) ProtoMessage()    {}
func (*SignRound1Message2) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{1}
}

func (m *SignRound1Message2) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound1Message2.Unmarshal(m, b)
}
func (m *SignRound1Message2) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound1Message2.Marshal(b, m, deterministic)
}
func (m *SignRound1Message2) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound1Message2.Merge(m, src)
}
func (m *SignRound1Message2) XXX_Size() int {
	return xxx_messageInfo_SignRound1Message2.Size(m)
}
func (m *SignRound1Message2) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound1Message2.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound1Message2 proto.InternalMessageInfo

func (m *SignRound1Message2) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

//
// Represents a P2P message sent to each party during Round 2 of the ECDSA TSS signing protocol.
type SignRound2Message struct {
	C1                   []byte   `protobuf:"bytes,1,opt,name=c1,proto3" json:"c1,omitempty"`
	C2                   []byte   `protobuf:"bytes,2,opt,name=c2,proto3" json:"c2,omitempty"`
	ProofBob             [][]byte `protobuf:"bytes,3,rep,name=proof_bob,json=proofBob,proto3" json:"proof_bob,omitempty"`
	ProofBobWc           [][]byte `protobuf:"bytes,4,rep,name=proof_bob_wc,json=proofBobWc,proto3" json:"proof_bob_wc,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound2Message) Reset()         { *m = SignRound2Message{} }
func (m *SignRound2Message) String() string { return proto.CompactTextString(m) }
func (*SignRound2Message) ProtoMessage()    {}
func (*SignRound2Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{2}
}

func (m *SignRound2Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound2Message.Unmarshal(m, b)
}
func (m *SignRound2Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound2Message.Marshal(b, m, deterministic)
}
func (m *SignRound2Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound2Message.Merge(m, src)
}
func (m *SignRound2Message) XXX_Size() int {
	return xxx_messageInfo_SignRound2Message.Size(m)
}
func (m *SignRound2Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound2Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound2Message proto.InternalMessageInfo

func (m *SignRound2Message) GetC1() []byte {
	if m != nil {
		return m.C1
	}
	return nil
}

func (m *SignRound2Message) GetC2() []byte {
	if m != nil {
		return m.C2
	}
	return nil
}

func (m *SignRound2Message) GetProofBob() [][]byte {
	if m != nil {
		return m.ProofBob
	}
	return nil
}

func (m *SignRound2Message) GetProofBobWc() [][]byte {
	if m != nil {
		return m.ProofBobWc
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 3 of the ECDSA TSS signing protocol.
type SignRound3Message struct {
	Theta                []byte   `protobuf:"bytes,1,opt,name=theta,proto3" json:"theta,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound3Message) Reset()         { *m = SignRound3Message{} }
func (m *SignRound3Message) String() string { return proto.CompactTextString(m) }
func (*SignRound3Message) ProtoMessage()    {}
func (*SignRound3Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{3}
}

func (m *SignRound3Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound3Message.Unmarshal(m, b)
}
func (m *SignRound3Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound3Message.Marshal(b, m, deterministic)
}
func (m *SignRound3Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound3Message.Merge(m, src)
}
func (m *SignRound3Message) XXX_Size() int {
	return xxx_messageInfo_SignRound3Message.Size(m)
}
func (m *SignRound3Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound3Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound3Message proto.InternalMessageInfo

func (m *SignRound3Message) GetTheta() []byte {
	if m != nil {
		return m.Theta
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 4 of the ECDSA TSS signing protocol.
type SignRound4Message struct {
	DeCommitment         [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	ProofAlphaX          []byte   `protobuf:"bytes,2,opt,name=proof_alpha_x,json=proofAlphaX,proto3" json:"proof_alpha_x,omitempty"`
	ProofAlphaY          []byte   `protobuf:"bytes,3,opt,name=proof_alpha_y,json=proofAlphaY,proto3" json:"proof_alpha_y,omitempty"`
	ProofT               []byte   `protobuf:"bytes,4,opt,name=proof_t,json=proofT,proto3" json:"proof_t,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound4Message) Reset()         { *m = SignRound4Message{} }
func (m *SignRound4Message) String() string { return proto.CompactTextString(m) }
func (*SignRound4Message) ProtoMessage()    {}
func (*SignRound4Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{4}
}

func (m *SignRound4Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound4Message.Unmarshal(m, b)
}
func (m *SignRound4Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound4Message.Marshal(b, m, deterministic)
}
func (m *SignRound4Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound4Message.Merge(m, src)
}
func (m *SignRound4Message) XXX_Size() int {
	return xxx_messageInfo_SignRound4Message.Size(m)
}
func (m *SignRound4Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound4Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound4Message proto.InternalMessageInfo

func (m *SignRound4Message) GetDeCommitment() [][]byte {
	if m != nil {
		return m.DeCommitment
	}
	return nil
}

func (m *SignRound4Message) GetProofAlphaX() []byte {
	if m != nil {
		return m.ProofAlphaX
	}
	return nil
}

func (m *SignRound4Message) GetProofAlphaY() []byte {
	if m != nil {
		return m.ProofAlphaY
	}
	return nil
}

func (m *SignRound4Message) GetProofT() []byte {
	if m != nil {
		return m.ProofT
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 5 of the ECDSA TSS signing protocol.
type SignRound5Message struct {
	Commitment           []byte   `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound5Message) Reset()         { *m = SignRound5Message{} }
func (m *SignRound5Message) String() string { return proto.CompactTextString(m) }
func (*SignRound5Message) ProtoMessage()    {}
func (*SignRound5Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{5}
}

func (m *SignRound5Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound5Message.Unmarshal(m, b)
}
func (m *SignRound5Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound5Message.Marshal(b, m, deterministic)
}
func (m *SignRound5Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound5Message.Merge(m, src)
}
func (m *SignRound5Message) XXX_Size() int {
	return xxx_messageInfo_SignRound5Message.Size(m)
}
func (m *SignRound5Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound5Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound5Message proto.InternalMessageInfo

func (m *SignRound5Message) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 6 of the ECDSA TSS signing protocol.
type SignRound6Message struct {
	DeCommitment         [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	ProofAlphaX          []byte   `protobuf:"bytes,2,opt,name=proof_alpha_x,json=proofAlphaX,proto3" json:"proof_alpha_x,omitempty"`
	ProofAlphaY          []byte   `protobuf:"bytes,3,opt,name=proof_alpha_y,json=proofAlphaY,proto3" json:"proof_alpha_y,omitempty"`
	ProofT               []byte   `protobuf:"bytes,4,opt,name=proof_t,json=proofT,proto3" json:"proof_t,omitempty"`
	VProofAlphaX         []byte   `protobuf:"bytes,5,opt,name=v_proof_alpha_x,json=vProofAlphaX,proto3" json:"v_proof_alpha_x,omitempty"`
	VProofAlphaY         []byte   `protobuf:"bytes,6,opt,name=v_proof_alpha_y,json=vProofAlphaY,proto3" json:"v_proof_alpha_y,omitempty"`
	VProofT              []byte   `protobuf:"bytes,7,opt,name=v_proof_t,json=vProofT,proto3" json:"v_proof_t,omitempty"`
	VProofU              []byte   `protobuf:"bytes,8,opt,name=v_proof_u,json=vProofU,proto3" json:"v_proof_u,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound6Message) Reset()         { *m = SignRound6Message{} }
func (m *SignRound6Message) String() string { return proto.CompactTextString(m) }
func (*SignRound6Message) ProtoMessage()    {}
func (*SignRound6Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{6}
}

func (m *SignRound6Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound6Message.Unmarshal(m, b)
}
func (m *SignRound6Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound6Message.Marshal(b, m, deterministic)
}
func (m *SignRound6Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound6Message.Merge(m, src)
}
func (m *SignRound6Message) XXX_Size() int {
	return xxx_messageInfo_SignRound6Message.Size(m)
}
func (m *SignRound6Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound6Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound6Message proto.InternalMessageInfo

func (m *SignRound6Message) GetDeCommitment() [][]byte {
	if m != nil {
		return m.DeCommitment
	}
	return nil
}

func (m *SignRound6Message) GetProofAlphaX() []byte {
	if m != nil {
		return m.ProofAlphaX
	}
	return nil
}

func (m *SignRound6Message) GetProofAlphaY() []byte {
	if m != nil {
		return m.ProofAlphaY
	}
	return nil
}

func (m *SignRound6Message) GetProofT() []byte {
	if m != nil {
		return m.ProofT
	}
	return nil
}

func (m *SignRound6Message) GetVProofAlphaX() []byte {
	if m != nil {
		return m.VProofAlphaX
	}
	return nil
}

func (m *SignRound6Message) GetVProofAlphaY() []byte {
	if m != nil {
		return m.VProofAlphaY
	}
	return nil
}

func (m *SignRound6Message) GetVProofT() []byte {
	if m != nil {
		return m.VProofT
	}
	return nil
}

func (m *SignRound6Message) GetVProofU() []byte {
	if m != nil {
		return m.VProofU
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 7 of the ECDSA TSS signing protocol.
type SignRound7Message struct {
	Commitment           []byte   `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound7Message) Reset()         { *m = SignRound7Message{} }
func (m *SignRound7Message) String() string { return proto.CompactTextString(m) }
func (*SignRound7Message) ProtoMessage()    {}
func (*SignRound7Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{7}
}

func (m *SignRound7Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound7Message.Unmarshal(m, b)
}
func (m *SignRound7Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound7Message.Marshal(b, m, deterministic)
}
func (m *SignRound7Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound7Message.Merge(m, src)
}
func (m *SignRound7Message) XXX_Size() int {
	return xxx_messageInfo_SignRound7Message.Size(m)
}
func (m *SignRound7Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound7Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound7Message proto.InternalMessageInfo

func (m *SignRound7Message) GetCommitment() []byte {
	if m != nil {
		return m.Commitment
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 8 of the ECDSA TSS signing protocol.
type SignRound8Message struct {
	DeCommitment         [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound8Message) Reset()         { *m = SignRound8Message{} }
func (m *SignRound8Message) String() string { return proto.CompactTextString(m) }
func (*SignRound8Message) ProtoMessage()    {}
func (*SignRound8Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{8}
}

func (m *SignRound8Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound8Message.Unmarshal(m, b)
}
func (m *SignRound8Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound8Message.Marshal(b, m, deterministic)
}
func (m *SignRound8Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound8Message.Merge(m, src)
}
func (m *SignRound8Message) XXX_Size() int {
	return xxx_messageInfo_SignRound8Message.Size(m)
}
func (m *SignRound8Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound8Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound8Message proto.InternalMessageInfo

func (m *SignRound8Message) GetDeCommitment() [][]byte {
	if m != nil {
		return m.DeCommitment
	}
	return nil
}

//
// Represents a BROADCAST message sent to all parties during Round 9 of the ECDSA TSS signing protocol.
type SignRound9Message struct {
	S                    []byte   `protobuf:"bytes,1,opt,name=s,proto3" json:"s,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRound9Message) Reset()         { *m = SignRound9Message{} }
func (m *SignRound9Message) String() string { return proto.CompactTextString(m) }
func (*SignRound9Message) ProtoMessage()    {}
func (*SignRound9Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_d7fd069ec73c8494, []int{9}
}

func (m *SignRound9Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRound9Message.Unmarshal(m, b)
}
func (m *SignRound9Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRound9Message.Marshal(b, m, deterministic)
}
func (m *SignRound9Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRound9Message.Merge(m, src)
}
func (m *SignRound9Message) XXX_Size() int {
	return xxx_messageInfo_SignRound9Message.Size(m)
}
func (m *SignRound9Message) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRound9Message.DiscardUnknown(m)
}

var xxx_messageInfo_SignRound9Message proto.InternalMessageInfo

func (m *SignRound9Message) GetS() []byte {
	if m != nil {
		return m.S
	}
	return nil
}

func init() {
	proto.RegisterType((*SignRound1Message1)(nil), "binance.tsslib.ecdsa.signing.SignRound1Message1")
	proto.RegisterType((*SignRound1Message2)(nil), "binance.tsslib.ecdsa.signing.SignRound1Message2")
	proto.RegisterType((*SignRound2Message)(nil), "binance.tsslib.ecdsa.signing.SignRound2Message")
	proto.RegisterType((*SignRound3Message)(nil), "binance.tsslib.ecdsa.signing.SignRound3Message")
	proto.RegisterType((*SignRound4Message)(nil), "binance.tsslib.ecdsa.signing.SignRound4Message")
	proto.RegisterType((*SignRound5Message)(nil), "binance.tsslib.ecdsa.signing.SignRound5Message")
	proto.RegisterType((*SignRound6Message)(nil), "binance.tsslib.ecdsa.signing.SignRound6Message")
	proto.RegisterType((*SignRound7Message)(nil), "binance.tsslib.ecdsa.signing.SignRound7Message")
	proto.RegisterType((*SignRound8Message)(nil), "binance.tsslib.ecdsa.signing.SignRound8Message")
	proto.RegisterType((*SignRound9Message)(nil), "binance.tsslib.ecdsa.signing.SignRound9Message")
}

func init() { proto.RegisterFile("ecdsa-signing.proto", fileDescriptor_d7fd069ec73c8494) }

var fileDescriptor_d7fd069ec73c8494 = []byte{
	// 409 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcc, 0x93, 0xc1, 0x8b, 0x13, 0x31,
	0x14, 0xc6, 0x99, 0xe9, 0x6e, 0xbb, 0xfb, 0x9c, 0x5a, 0x36, 0x0a, 0x06, 0x15, 0xa9, 0x11, 0x61,
	0x15, 0x1c, 0x99, 0xe9, 0xaa, 0xeb, 0xd1, 0xf5, 0xac, 0x2c, 0xb5, 0xa2, 0xf5, 0x32, 0x64, 0x32,
	0x71, 0x3a, 0xd0, 0x26, 0xc3, 0x24, 0xad, 0xf6, 0x4f, 0xf1, 0xe4, 0xbf, 0x2a, 0xcd, 0x24, 0x25,
	0x6d, 0x05, 0xf5, 0xe6, 0xf1, 0xbd, 0xef, 0xf7, 0xf2, 0xbd, 0x7c, 0xf0, 0xe0, 0x16, 0x67, 0x85,
	0xa2, 0xcf, 0x54, 0x55, 0x8a, 0x4a, 0x94, 0x71, 0xdd, 0x48, 0x2d, 0xd1, 0xfd, 0xbc, 0x12, 0x54,
	0x30, 0x1e, 0x6b, 0xa5, 0xe6, 0x55, 0x1e, 0x1b, 0x26, 0xb6, 0x0c, 0x79, 0x0f, 0xe8, 0x43, 0x55,
	0x8a, 0xb1, 0x5c, 0x8a, 0x22, 0x79, 0xc7, 0x95, 0xa2, 0x25, 0x4f, 0x50, 0x04, 0x01, 0xc3, 0xc1,
	0x30, 0x38, 0x8f, 0xc6, 0x01, 0x43, 0x4f, 0xe1, 0xac, 0xa1, 0xa2, 0xe4, 0x59, 0xdd, 0x48, 0xf9,
	0x35, 0xa3, 0xf3, 0x8a, 0x71, 0x1c, 0x0e, 0x3b, 0xe7, 0xd1, 0x78, 0x60, 0x84, 0xeb, 0x4d, 0xff,
	0xcd, 0xa6, 0x4d, 0x2e, 0x7e, 0xf3, 0x5e, 0x8a, 0x1e, 0x00, 0x30, 0xb9, 0x58, 0x54, 0x7a, 0xc1,
	0x85, 0xb6, 0x0f, 0x7b, 0x1d, 0xd2, 0xc0, 0xd9, 0x76, 0x2a, 0xb5, 0x53, 0xe8, 0x26, 0x84, 0x2c,
	0xb1, 0x70, 0xc8, 0x12, 0x53, 0xa7, 0x38, 0xb4, 0x75, 0x8a, 0xee, 0xc1, 0x69, 0xbb, 0x50, 0x2e,
	0x73, 0xdc, 0x31, 0xeb, 0x9c, 0x98, 0xc6, 0x95, 0xcc, 0xd1, 0x10, 0xa2, 0xad, 0x98, 0x7d, 0x63,
	0xf8, 0xc8, 0xe8, 0xe0, 0xf4, 0x4f, 0x8c, 0x3c, 0xf1, 0x3c, 0x47, 0xce, 0xf3, 0x36, 0x1c, 0xeb,
	0x19, 0xd7, 0xd4, 0xda, 0xb6, 0x05, 0xf9, 0x11, 0x78, 0xec, 0x85, 0x63, 0x1f, 0x41, 0xbf, 0xe0,
	0xd9, 0xce, 0xbf, 0x36, 0x1e, 0x51, 0xc1, 0xdf, 0x6e, 0x7b, 0x88, 0x40, 0xdf, 0xa5, 0x56, 0xcf,
	0x68, 0xf6, 0xdd, 0xee, 0x7f, 0xa3, 0x6e, 0x23, 0xab, 0x67, 0xf4, 0xf3, 0x3e, 0xb3, 0xc6, 0x9d,
	0x7d, 0x66, 0x8a, 0xee, 0x40, 0xaf, 0x65, 0x34, 0x3e, 0x32, 0x6a, 0xd7, 0x94, 0x13, 0x32, 0xf2,
	0x56, 0x7b, 0xe1, 0x56, 0xfb, 0x53, 0xde, 0x3f, 0x43, 0x6f, 0xea, 0xe5, 0x7f, 0xf5, 0x21, 0xf4,
	0x18, 0x06, 0xab, 0x6c, 0xd7, 0xe2, 0xd8, 0x00, 0xd1, 0xea, 0xda, 0xf3, 0x38, 0xc0, 0xd6, 0xb8,
	0x7b, 0x80, 0x4d, 0xd1, 0x5d, 0x38, 0x75, 0x98, 0xc6, 0x3d, 0x03, 0xf4, 0x5a, 0x60, 0xe2, 0x6b,
	0x4b, 0x7c, 0xe2, 0x6b, 0x1f, 0x77, 0x62, 0x7d, 0xf5, 0xb7, 0xb1, 0x5e, 0x7a, 0x43, 0x97, 0xff,
	0x92, 0x2a, 0x79, 0xe8, 0x4d, 0xbe, 0x76, 0x93, 0x11, 0x04, 0xca, 0x5d, 0xa1, 0xba, 0x1a, 0x7c,
	0xe9, 0x9b, 0xd3, 0x7d, 0x6e, 0x4f, 0x37, 0xef, 0x9a, 0xfb, 0x1e, 0xfd, 0x0a, 0x00, 0x00, 0xff,
	0xff, 0x63, 0x2f, 0x21, 0x2c, 0xf6, 0x03, 0x00, 0x00,
}
