/* CONFIGURE SERVER */
#define MAX_CLIENTS 5
#define PORT 8888 //PORT_UDP == PORT_TCP
#define ADDRESS "0.0.0.0"

#define MAX_PATH_SIZE 256
#define ALPHABET_SIZE 256  // TamaÃ±o de alfabeto (ASCII)

char path_dir_zones[MAX_PATH_SIZE] = "../dns/zones/";  //files of zone
char psl_path_file[MAX_PATH_SIZE] = "../dns/public_suffix_list.dat.txt";

int RECURSION_ACTIVATE = -1;  // 0 = true, -1 = false
int REQUESTSTATUS = 0;

int aa = 0;

typedef struct {
  struct TrieNode *children[ALPHABET_SIZE];
  int isEndOfDomain;
  int domainID;
} TrieNode;
