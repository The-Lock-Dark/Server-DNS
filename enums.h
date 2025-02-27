//TYPE Values
#define A 1
#define NS 2
#define MD 3
#define MF 4
#define CNAME 5
#define SOA 6
#define MB 7
#define MG 8
#define MR 9
#define _NULL 10
#define WKS 11
#define PTR 12
#define HINFO 13
#define MINFO 14
#define MX 15
#define TXT 16
#define AAAA 28

//QTYPE Values
#define AXFR = 252;
#define MAILB = 253;
#define MAILA = 254;
//#define * = 255;

//CLASS Values
#define IN 1
#define CS 2
#define CH 3
#define HS 4

//QCLASS Values
//#define * = 255;


/* OPCODE */
#define QUERY 0
#define IQUERY 1
#define STATUS 2
//3-15 reserved

/* RCODE */
#define NOERROR 0
#define FORMERR 1
#define SERVFAIL 2
#define NXDOMAIN 3
#define NOTIMP 4
#define REFUSED 5
//EXTENSION DNS...

#define MAX_SIZE_LABEL 63
#define MAX_SIZE_NAMES 255
#define MAX_AMOUNT_SPOT 126
#define MAX_SIZE_MESSAGE_UDP 512 //rfc 1034 y 1035
#define MAX_SIZE_MESSAGE_UDP_EDNS 4096 //rfc 6891
#define MAX_SIZE_MESSAGE_TCP 65535
#define MAX_SIZE_LINE 2048

#define MAX_SIZE_REQUESTS 65535

#define MAX_AMOUNT_NAMES 10              //IMPORTANT!!


//CLIENT
typedef struct {
  uint16_t id: 16;        //16 bits
  unsigned int  qr: 1;    //1 bit
  unsigned int opcode: 4; //4 bits
  unsigned int aa: 1;     //1 bit
  unsigned int tc: 1;     //1 bit
  unsigned int rd: 1;     //1 bit
  unsigned int ra: 1;     //1 bit
  unsigned int z: 1;      //debe ser 0 siempre
  unsigned int rcode: 4;  //4 bits
  unsigned int ad: 1;     //1 bit
  unsigned int nauth: 1;  //1 bit
  uint16_t qdcount: 16;   //16 bits
  uint16_t ancount: 16;   //16 bits
  uint16_t nscount: 16;   //16 bits
  uint16_t arcount: 16;   //16 bits
} HeaderClient;

typedef struct {
  unsigned char qname[MAX_SIZE_NAMES];
  uint16_t qtype;
  uint16_t qclass;
} Question;

typedef struct {
  char name[MAX_SIZE_NAMES];
  uint16_t type;
  uint16_t _class;
  uint8_t rcode_extend;
  uint8_t version;
  uint16_t z;
  uint32_t ttl;
  uint16_t rdlength;
  char rdata[MAX_SIZE_MESSAGE_UDP];
} ResourceRecord;


//SERVER
typedef struct {
  uint16_t id: 16;        //16 bits
  unsigned int  qr: 1;    //1 bit
  unsigned int opcode: 4; //4 bits
  unsigned int aa: 1;     //1 bit
  unsigned int tc: 1;     //1 bit
  unsigned int rd: 1;     //1 bit
  unsigned int ra: 1;     //1 bit
  unsigned int z: 1;      //debe ser 0 siempre
  uint8_t rcode: 4;  //4 bits
  unsigned int ad: 1;     //1 bit
  unsigned int nauth: 1;  //1 bit
  uint16_t qdcount: 16;   //16 bits
  uint16_t ancount: 16;   //16 bits
  uint16_t nscount: 16;   //16 bits
  uint16_t arcount: 16;   //16 bits
} HeaderServer;

typedef struct {
  unsigned char name[MAX_SIZE_NAMES];         //utiliza el formato de dns -> 3www6google3com
  uint16_t type;
  uint16_t _class;
  uint8_t rcode_extend;
  uint8_t version;
  uint16_t z;
  uint32_t ttl;
  uint16_t rdlength;
  uint8_t rdata[MAX_SIZE_MESSAGE_UDP];
} Response;


typedef struct {
  HeaderClient headclient;
  Question question[MAX_SIZE_REQUESTS];
  ResourceRecord rrcord[MAX_SIZE_REQUESTS];
  HeaderServer headserver;
  Response response[MAX_SIZE_REQUESTS];
} Format;

struct Format_RR {
  char name[MAX_SIZE_NAMES];
  int type; //0
  int cls; //0
  int32_t ttl; //0
  int len_r; //0
  char rdata[];
};

struct FormatSoRData {
  char mname[MAX_SIZE_NAMES];
  char rname[MAX_SIZE_NAMES];
  uint32_t serie;
  int32_t update;
  int32_t retry;
  int32_t expire;
  uint32_t min;
};

struct FormatTXT {
  char txtdata[MAX_SIZE_MESSAGE_UDP];
};

struct InetSpecificRR {
  struct {
    uint32_t addr;
  }a;
  struct {
    uint32_t addr;
    int8_t protocol;
    int* bitmap;
  }Wks;
};

struct FormatsRData {
  struct {
    char cname[MAX_SIZE_NAMES];
  } CName;
  struct {
    char cpu[MAX_SIZE_MESSAGE_UDP];
    char so[MAX_SIZE_MESSAGE_UDP];
  } HInfo;
  struct {
    char madname[MAX_SIZE_NAMES];
  } Mb;
  struct {
    char madname[MAX_SIZE_NAMES];
  } Md;
  struct {
    char madname[MAX_SIZE_NAMES];
  } Mf;
  struct {
    char mgmname[MAX_SIZE_NAMES];
  } Mg;
  struct {
    char rmailbx[MAX_SIZE_NAMES];
    char emailbx[MAX_SIZE_NAMES];
  } MInfo;
  struct {
    char newname[MAX_SIZE_NAMES];
  } Mr;
  struct {
    uint16_t preference;
    char exchanges[MAX_SIZE_NAMES];
  } Mx;
  struct {
    int null;
  } Null;
  struct {
    char nsdname[MAX_SIZE_NAMES];
  } Ns;
  struct {
    char ptrdname[MAX_SIZE_NAMES];
  } Ptr;
};
