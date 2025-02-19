#include "main.h"

using namespace core;
using namespace NIST256;
//曲线NIST256，包含大整数BIG
using namespace B256_56;

//定义随机数生成器
csprng rng;
keyStruct key;

void initRNG(core::csprng *rng)
{
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    unsigned long ran;
    time((time_t *)&ran);
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i;
    CREATE_CSPRNG(rng, &RAW);
}

keyStruct getKey(ECP G,BIG order) {
    keyStruct key;
    //私钥
    BIG_randomnum(key.sk,order,&rng);
    //公钥
    ECP_copy(&key.PK,&G);
    ECP_mul(&key.PK,key.sk);
    return key;
}

publicStruct init() {
    publicStruct pub;
    //获取椭圆曲线基点 G 和阶 q
    ECP_generator(&pub.G);
    BIG_rcopy(pub.order,CURVE_Order);
    key=getKey(pub.G,pub.order);
    pub.PK=key.PK;
    return pub;
}

/*
 * 非交互式schnorr签名
 * 1、Alice 生成公私钥，
 * 2、Alice 随机选择一个r，并依次计算 R=r*G ，c=Hash（R，PK），z=r+c*sk，其中schnorr签名为（R，z）
 * ps. 随机数 r 通过伪随机数生成器生成 void initRNG(core::csprng *rng);
 *     其中 CREATE_CSPRNG(rng, &RAW);需要添加头文件 #include "randapi.h"
 * 3、BoB 开始验证
 *  （1、计算 c = Hash（R，PK）
 *  （2、验证 z*G = R+c*PK
 */
schnorrStruct schnorr(keyStruct key,publicStruct pub,char message[]) {

    schnorrStruct sig;
    //选择随机数r
    BIG r;
    BIG_randomnum(r,pub.order,&rng);

    //计算 R=r*G
    //ECP R;
    ECP_copy(&sig.R,&pub.G);
    ECP_mul(&sig.R,r);

    //计算c=Hash(R，PK)
    hash256 sha;
    char hashstr[32];
    memset(hashstr,0,32);
    HASH256_init(&sha);

    BIG x,y;
    BIG c;
    ECP_get(x,y,&sig.R);
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)x)[j]);
    }
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)y)[j]);
    }
    ECP_get(x,y,&key.PK);
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)x)[j]);
    }
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)y)[j]);
    }
    for(int j=0;j<strlen(message);j++){
        HASH256_process(&sha,message[j]);
    }
    HASH256_hash(&sha,hashstr);
    BIG_fromBytesLen(c,hashstr,32);
    BIG_mod(c,pub.order);

    //计算z
    //BIG z;
    BIG_modmul(sig.z,c,key.sk,pub.order);
    BIG_modadd(sig.z,sig.z,r,pub.order);
    return sig;
}

void testSchnorr(char message[],publicStruct pub,schnorrStruct sig) {
    // 1、计算 c = Hash（R，PK）
    //计算c=Hash(R，PK)
    hash256 sha;
    char hashstr[32];
    memset(hashstr,0,32);
    HASH256_init(&sha);

    BIG x,y;
    BIG c;
    ECP_get(x,y,&sig.R);
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)x)[j]);
    }
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)y)[j]);
    }
    ECP_get(x,y,&pub.PK);
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)x)[j]);
    }
    for(int j=0;j<sizeof(BIG);j++){
        HASH256_process(&sha,((char*)y)[j]);
    }
    for(int j=0;j<strlen(message);j++){
        HASH256_process(&sha,message[j]);
    }
    HASH256_hash(&sha,hashstr);
    BIG_fromBytesLen(c,hashstr,32);
    BIG_mod(c,pub.order);

    // 2、验证 z*G = R+c*PK
    ECP zG;
    ECP_copy(&zG,&pub.G);
    ECP_mul(&zG,sig.z);

    ECP RcP;
    ECP_copy(&RcP,&pub.PK);
    ECP_mul(&RcP,c);
    ECP_add(&RcP,&sig.R);

    if(ECP_equals(&zG,&RcP)==1){
        printf("OK\n");
    }
    else {
        printf("FAIL\n");
    }
}


int main() {
    static char message[] = "This is a test message";
    publicStruct pub = init();
    schnorrStruct sig = schnorr(key,pub,message);
    testSchnorr(message,pub,sig);
    return 0;
}