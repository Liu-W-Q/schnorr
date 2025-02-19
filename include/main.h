#include <iostream>
#include <string.h>
#include <core.h>
#include "randapi.h"
//选择NIST256曲线
#include "ecp_NIST256.h"

using namespace core;
using namespace NIST256;
//曲线NIST256，包含大整数BIG
using namespace B256_56;

struct keyStruct {
    BIG sk;
    ECP PK;
};

struct publicStruct {
    ECP PK;
    ECP G;
    BIG order;
};

struct schnorrStruct {
    ECP R;
    BIG z;
};

keyStruct getKey(ECP G,BIG order);

publicStruct init();

void initRNG(core::csprng *rng);

schnorrStruct schnorr(publicStruct pub,char message[]);

void testSchnorr(char message[],publicStruct pub,schnorrStruct sig);