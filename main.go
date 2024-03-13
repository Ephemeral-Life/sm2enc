package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/Ephemeral-Life/sm2enc/pb"
	"github.com/Ephemeral-Life/sm2enc/sm/sm2"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"net"
)

func init() {
	// 注册需要序列化的类型，确保 gob 编解码器知道如何处理这些类型
	gob.Register(&sm2.PublicKey{})
	gob.Register(&sm2.PrivateKey{})
}

func serializePublicKey(pk *sm2.PublicKey) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(pk); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func deserializePublicKey(data []byte) (*sm2.PublicKey, error) {
	var pk sm2.PublicKey
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

func serializePrivateKey(sk *sm2.PrivateKey) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(sk); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func deserializePrivateKey(data []byte) (*sm2.PrivateKey, error) {
	var sk sm2.PrivateKey
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&sk); err != nil {
		return nil, err
	}
	return &sk, nil
}

func generateSM2KeyPair() (*sm2.PrivateKey, *sm2.PublicKey, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader) // 使用SM2库生成密钥对
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey // 获取公钥
	return privateKey, publicKey, nil
}

func encryptIntWithPublicKey(pk *sm2.PublicKey, plaintext int64) (c1x, c1y, c2x, c2y *big.Int) {
	m_big := big.NewInt(plaintext)
	c1x, c1y, c2x, c2y = sm2.LgwHEnc(rand.Reader, pk, m_big)
	return c1x, c1y, c2x, c2y
}

func decryptIntWithPrivateKey(sk *sm2.PrivateKey, c1x, c1y, c2x, c2y *big.Int) (plaintext int, err error) {
	plaintext, err = sm2.LgwHDec(sk, c1x, c1y, c2x, c2y)
	if err != nil {
		fmt.Printf("解密时出错: %s\n", err)
		return 0, err
	}
	return plaintext, nil
}

func homomorphicAdd(pk *sm2.PublicKey, c1x1, c1y1, c2x1, c2y1, c1x2, c1y2, c2x2, c2y2 *big.Int) (sumC1x, sumC1y, sumC2x, sumC2y *big.Int) {
	sumC1x, sumC1y = pk.Curve.Add(c1x1, c1y1, c1x2, c1y2)
	sumC2x, sumC2y = pk.Curve.Add(c2x1, c2y1, c2x2, c2y2)
	return sumC1x, sumC1y, sumC2x, sumC2y
}

type server struct {
	pb.UnimplementedSM2CryptoServiceServer
}

func (s *server) GenerateKeyPair(ctx context.Context, in *pb.Empty) (*pb.KeyPair, error) {
	// 这里应调用之前定义的生成密钥对的函数，下同
	privateKey, publicKey, err := generateSM2KeyPair()
	if err != nil {
		log.Printf("生成密钥对失败: %v", err)
		return nil, err
	}

	// 序列化私钥和公钥
	serializedPrivateKey, err := serializePrivateKey(privateKey)
	if err != nil {
		log.Printf("序列化私钥失败: %v", err)
		return nil, err
	}

	serializedPublicKey, err := serializePublicKey(publicKey)
	if err != nil {
		log.Printf("序列化公钥失败: %v", err)
		return nil, err
	}

	// 这里应当根据实际 protobuf 的 KeyPair 结构来构建返回值
	// 假设 KeyPair 有 PrivateKey 和 PublicKey 两个字段，类型都是 []byte
	return &pb.KeyPair{
		PrivateKey: serializedPrivateKey,
		PublicKey:  serializedPublicKey,
	}, nil
}

func (s *server) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	// 加密逻辑
	return &pb.EncryptResponse{}, nil
}

func (s *server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	// 解密逻辑
	return &pb.DecryptResponse{}, nil
}

func (s *server) HomomorphicAdd(ctx context.Context, req *pb.HomomorphicAddRequest) (*pb.HomomorphicAddResponse, error) {
	// 同态加法逻辑
	return &pb.HomomorphicAddResponse{}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterSM2CryptoServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
