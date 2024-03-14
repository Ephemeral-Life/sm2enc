package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/Ephemeral-Life/sm2enc/pb"
	"github.com/Ephemeral-Life/sm2enc/sm/sm2"
	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"net"
)

func init() {
	gob.Register(&big.Int{})
}

type SerializedPrivateKey struct {
	D []byte // 私钥 D 的字节表示
}

type SerializedPublicKey struct {
	X []byte // 公钥 X 坐标的字节表示
	Y []byte // 公钥 Y 坐标的字节表示
}

func serializePrivateKey(sk *sm2.PrivateKey) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	serialized := SerializedPrivateKey{
		D: sk.D.Bytes(),
	}
	if err := encoder.Encode(serialized); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func deserializePrivateKey(data []byte) (*sm2.PrivateKey, error) {
	var serialized SerializedPrivateKey
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&serialized); err != nil {
		return nil, err
	}
	sk := &sm2.PrivateKey{
		D: new(big.Int).SetBytes(serialized.D),
		// PublicKey 需要适当初始化
	}
	sk.PublicKey.Curve = sm2curve.P256() // 重新设置曲线
	sk.PublicKey.X, sk.PublicKey.Y = sk.PublicKey.Curve.ScalarBaseMult(serialized.D)
	return sk, nil
}

func serializePublicKey(pk *sm2.PublicKey) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	serialized := SerializedPublicKey{
		X: pk.X.Bytes(),
		Y: pk.Y.Bytes(),
	}
	if err := encoder.Encode(serialized); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func deserializePublicKey(data []byte) (*sm2.PublicKey, error) {
	var serialized SerializedPublicKey
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&serialized); err != nil {
		return nil, err
	}
	pk := &sm2.PublicKey{
		Curve: sm2curve.P256(),
		X:     new(big.Int).SetBytes(serialized.X),
		Y:     new(big.Int).SetBytes(serialized.Y),
	}
	return pk, nil
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
	fmt.Printf("privateKey: %+v\n", privateKey)
	fmt.Printf("publicKey: %+v\n", publicKey)
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
	// 反序列化公钥
	publicKey, err := deserializePublicKey(req.PublicKey)
	fmt.Printf("Encrypt publicKey: %+v\n", publicKey)
	if err != nil {
		log.Printf("反序列化公钥失败: %v", err)
		return nil, err
	}

	// 使用公钥加密请求中的整数
	fmt.Printf("Encrypt Plaintext: %v\n", req.Plaintext)
	c1x, c1y, c2x, c2y := encryptIntWithPublicKey(publicKey, req.Plaintext)

	// 构建加密响应，这里假设pb.EncryptResponse中有C1x, C1y, C2x, C2y字段，它们都是[]byte类型
	// 实际protobuf结构可能有所不同，请根据实际情况调整
	response := &pb.EncryptResponse{
		C1X: c1x.Bytes(),
		C1Y: c1y.Bytes(),
		C2X: c2x.Bytes(),
		C2Y: c2y.Bytes(),
	}
	return response, nil
}

func (s *server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	// 解密逻辑
	// 反序列化私钥
	privateKey, err := deserializePrivateKey(req.PrivateKey)
	if err != nil {
		log.Printf("反序列化私钥失败: %v", err)
		return nil, err
	}

	// 将密文的坐标转换为big.Int
	c1x := new(big.Int).SetBytes(req.C1X)
	c1y := new(big.Int).SetBytes(req.C1Y)
	c2x := new(big.Int).SetBytes(req.C2X)
	c2y := new(big.Int).SetBytes(req.C2Y)

	// 使用私钥解密
	plaintext, err := decryptIntWithPrivateKey(privateKey, c1x, c1y, c2x, c2y)
	if err != nil {
		log.Printf("解密失败: %v", err)
		return nil, err
	}

	fmt.Printf("Decrypt Plaintext: %v\n", plaintext)

	// 构建解密响应，这里假设pb.DecryptResponse中有一个Plaintext字段，它是int64类型
	// 实际protobuf结构可能有所不同，请根据实际情况调整
	response := &pb.DecryptResponse{
		Plaintext: int64(plaintext),
	}

	return response, nil
}

func (s *server) HomomorphicAdd(ctx context.Context, req *pb.HomomorphicAddRequest) (*pb.HomomorphicAddResponse, error) {
	// 同态加法逻辑
	// 反序列化公钥
	publicKey, err := deserializePublicKey(req.PublicKey)
	if err != nil {
		log.Printf("反序列化公钥失败: %v", err)
		return nil, err
	}

	// 将请求中的密文坐标转换为big.Int
	c1x1 := new(big.Int).SetBytes(req.C1X1)
	c1y1 := new(big.Int).SetBytes(req.C1Y1)
	c2x1 := new(big.Int).SetBytes(req.C2X1)
	c2y1 := new(big.Int).SetBytes(req.C2Y1)

	c1x2 := new(big.Int).SetBytes(req.C1X2)
	c1y2 := new(big.Int).SetBytes(req.C1Y2)
	c2x2 := new(big.Int).SetBytes(req.C2X2)
	c2y2 := new(big.Int).SetBytes(req.C2Y2)

	// 执行同态加法操作
	sumC1x, sumC1y, sumC2x, sumC2y := homomorphicAdd(publicKey, c1x1, c1y1, c2x1, c2y1, c1x2, c1y2, c2x2, c2y2)

	// 构建同态加法响应，这里假设pb.HomomorphicAddResponse中有SumC1X, SumC1Y, SumC2X, SumC2Y字段，它们都是[]byte类型
	// 实际protobuf结构可能有所不同，请根据实际情况调整
	response := &pb.HomomorphicAddResponse{
		SumC1X: sumC1x.Bytes(),
		SumC1Y: sumC1y.Bytes(),
		SumC2X: sumC2x.Bytes(),
		SumC2Y: sumC2y.Bytes(),
	}

	return response, nil
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
