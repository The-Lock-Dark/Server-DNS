/* This server is only to see how the DNS protocol works, do not use it for production! */

/* Attention, this server has vulnerabilities, which is why its use in production is not recommended.
   Furthermore, this server was made while the author was learning about the C language.
   This code was intended to facilitate the implementation of more DNS extensions.
   This server only supports queries of type A and class IN, it is expected that more of these will be added
   in the future, I\O and a single thread are used for DNS queries */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <event2/event.h>

#include "enums.h"
#include "server.h"
#include "parser.c"


typedef struct {
  Format *format;
  struct sockaddr_in client_address;
  socklen_t client_length;
  evutil_socket_t fd;
} ClientData;

/* Agrega mas funciones a el servidor DNS */
int SIMPLE_SERVER_DNS = 1;  //1 = UP, 0 = DOWN;

int domainCounter = 0;
Dictionary QTypes[MAX_ITEMS];
Dictionary QClass[MAX_ITEMS];

void add_items() {

   /* QTYPES */
   add_item(QTypes, A, "A");

   /*  NOT SUPPORTED
   add_item(QTypes, NS, "NS");
   add_item(QTypes, MD, "MD");
   add_item(QTypes, MF, "MF");
   add_item(QTypes, CNAME, "CNAME");
   add_item(QTypes, SOA, "SOA");
   add_item(QTypes, MB, "MB");
   add_item(QTypes, MG, "MG");
   add_item(QTypes, MR, "MR");
   add_item(QTypes, _NULL, "NULL");
   add_item(QTypes, WKS, "WKS");
   add_item(QTypes, PTR, "PTR");
   add_item(QTypes, HINFO, "HINFO");
   add_item(QTypes, MINFO, "MINFO");
   add_item(QTypes, MX, "MX");
   add_item(QTypes, TXT, "TXT");
   add_item(QTypes, AAAA, "AAAA");
   */

   /* QCLASS */
   add_item(QClass, IN, "IN");

   /*  NOT SUPPORTED
   add_item(QClass, CS, "CS");
   add_item(QClass, CH, "CH");
   add_item(QClass, HS, "HS");
   */
}


// FunciÃ³n para crear un nodo Trie
TrieNode* createNode() {
    TrieNode *newNode = (TrieNode *)malloc(sizeof(TrieNode));
    newNode->isEndOfDomain = 0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        newNode->children[i] = NULL;
    }
    return newNode;
}

// FunciÃ³n para insertar un dominio en el Trie
void insertDomain(TrieNode *root, const char *domain) {
    TrieNode *current = root;
    for (int i = 0; i < strlen(domain); i++) {
        int index = domain[i];  // Ãndice basado en ASCII
        if (current->children[index] == NULL) {
            current->children[index] = (struct TrieNode *)createNode();
        }
        current = (TrieNode *)current->children[index];
    }
    current->isEndOfDomain = 1;
}

// FunciÃ³n para liberar memoria del Trie
void freeTrie(TrieNode *root) {
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (root->children[i]) {
            freeTrie((TrieNode *)root->children[i]);
        }
    }
    free(root);
}

// FunciÃ³n para buscar un dominio en el Trie
int searchDomain(TrieNode *root, const char *domain) {
    TrieNode *current = root;
    for (int i = 0; i < strlen(domain); i++) {
        int index = domain[i];
        if (current->children[index] == NULL) {
            return 0;  // No encontrado
        }
        current = (TrieNode *)current->children[index];
    }
    return current->isEndOfDomain;  // Devuelve 1 si es un dominio registrado
}

int insert_psl_load_file(TrieNode *root, const char *path) {
  TrieNode *current = root;
  char line[MAX_SIZE_LINE];
  FILE *file = fopen(path, "r");
  if (file != NULL) {
     while (fgets(line, MAX_SIZE_LINE, file) != NULL) {
       line[strcspn(line, "\r\n")] = 0;
       if (strstr(line, "//") == NULL && strlen(line) != 0) {
         insertDomain(current, line);
       }
     }
  } else {
    return -1;
  }
 fclose(file);
 return 0;
}

int response_authoritative() {
  return aa;
}

int truncated_bit_tc() {
  return 0;
}


void get_zone_file_address(uint8_t *rdata, Question question, TrieNode *root) {
  Dictionary dict[MAX_ITEMS];
  char filename[MAX_SIZE_NAMES];
  char subdomain[MAX_SIZE_LABEL];
  char path[MAX_PATH_SIZE];
  char line[MAX_SIZE_LINE];
  int class = -1, type = -1;
  int offset = 0;
  char *piece;

  memset(dict, 0, sizeof(dict));
  memset(path, 0, sizeof(path));
  memset(filename, 0, sizeof(filename));
  memset(subdomain, 0, sizeof(subdomain));

  piece = strtok((char *)question.qname, ".");
  while (piece != NULL) {
    add_item(dict, offset, piece);
    piece = strtok(NULL, ".");
    offset++;
  }

  int host = 0;
  for (int i=offset - 1; i>=0; i--) {
    char *result = get_value(dict, i);
    if (host == 0) {
      if (strlen(filename) > 0) {
        strcpy(result + strlen(result), ".");
        memmove(filename + strlen(result), filename, strlen(filename));
        memcpy(filename, result, strlen(result));
      } else {
        strcpy(filename, result);
      }

      if (searchDomain(root, filename) == 0) {
        strcpy(filename + strlen(filename), ".zone");
        host = i;
      }
    } else {
      if ((i + 1) != host) {
        strcpy(result + strlen(result), ".");
      }

      memmove(subdomain + strlen(result), subdomain, strlen(subdomain));
      memcpy(subdomain, result, strlen(result));
    }
  }

  if (subdomain[0] == '\0') {
    subdomain[0] = '@';
  }

  snprintf(path, MAX_PATH_SIZE, "%s%s", path_dir_zones, filename);
  piece = NULL;

  FILE *file = fopen(path, "r");
  if (file == NULL) {
    REQUESTSTATUS = NXDOMAIN;
    perror("");  //error al abrir el archivo
    return;
  }

  aa = 1;         //response authoritative

  while (fgets(line, MAX_SIZE_LINE, file) != NULL) {
       line[strcspn(line, "\n")] = '\0';

       // Si el subdomain no esta error
       if (startswith(line, subdomain) == 0) {     //solo el inicio
          piece = strtok(line, " ");
          while (piece != NULL) {
              if (strcmp(get_value(QClass, question.qclass), piece) == 0) {
                class = 0;
              }

              if (strcmp(get_value(QTypes, question.qtype), piece) == 0) {
                type = 0;
              }

              if (class == 0 && type == 0) {
                class = -1, type = -1;
                piece = strtok(NULL, " ");

                if (piece != NULL) {
                  pack_addr(rdata, piece);
                } else {
                  /* ERROR Â¡ADDRESS NOT FOUND! */
                  REQUESTSTATUS = NXDOMAIN;
                }
              } else {
                piece = strtok(NULL, " ");
              }
          }
       }
  }

  fclose(file);
}

void get_size_rdata(uint16_t *rdlength, uint8_t rdata[]) {
  /* Compatible only with ipv4 */
  int offset = 0;
  while (rdata[offset] != '\0') {
    *rdlength += sizeof(rdata[offset]);
    offset++;
  }
}

uint8_t unpack_uint8_t(unsigned char *data, int *offset) {
  uint8_t unpack_data = ntohs(*(uint8_t *)&data[*offset]);
  *offset += 1;
  return unpack_data;
}
uint16_t unpack_uint16_t(unsigned char *data, int *offset) {
  uint16_t unpack_data = ntohs(*(uint16_t *)&data[*offset]);
  *offset += 2;
  return unpack_data;
}

void pack_uint16_t(uint16_t data, unsigned char *buffer, size_t *offset) {
   uint16_t pack_data = htons(data);
   memcpy(buffer + *offset, &pack_data, 2);
   *offset += 2;
}

void pack_uint32_t(uint32_t data, unsigned char *buffer, size_t *offset) {
   uint32_t pack_data = htonl(data);
   memcpy(buffer + *offset, &pack_data, 4);
   *offset += 4;
}

void encoded_packet_header(HeaderServer header, unsigned char* buffer, size_t* offset) {
   pack_uint16_t(header.id, buffer, offset);

   // Construir el campo de flags (16 bits)
   uint16_t flags = 0;
   flags |= (header.qr & 0x1) << 15;
   flags |= (header.opcode & 0xF) << 11;
   flags |= (header.aa & 0x1) << 10;
   flags |= (header.tc & 0x1) << 9;
   flags |= (header.rd & 0x1) << 8;
   flags |= (header.ra & 0x1) << 7;
   flags |= (header.z & 0x1) << 6;
   flags |= (header.rcode & 0xF) << 0;

   pack_uint16_t(flags, buffer, offset);
   pack_uint16_t(header.qdcount, buffer, offset);
   pack_uint16_t(header.ancount, buffer, offset);
   pack_uint16_t(header.nscount, buffer, offset);
   pack_uint16_t(header.arcount, buffer, offset);

}

void encoded_packet_question(Question question, unsigned char* buffer, size_t* offset) {
   unsigned char name[MAX_SIZE_NAMES];
   memset(name, 0, sizeof(name));
   encoded_dns_format((char *)question.qname, name);
   size_t name_len = get_name_length(name, MAX_SIZE_NAMES);

   memcpy(buffer + *offset, name, name_len);
   *offset += name_len;

   pack_uint16_t(question.qtype, buffer, offset);
   pack_uint16_t(question.qclass, buffer, offset);
}

void encoded_packet_response(Response resp, unsigned char* buffer, size_t* offset) {
   size_t name_len = get_name_length(resp.name, MAX_SIZE_NAMES);
   memcpy(buffer + *offset, resp.name, name_len);
   *offset += name_len;

   pack_uint16_t(resp.type, buffer, offset);
   pack_uint16_t(resp._class, buffer, offset);
   pack_uint32_t(resp.ttl, buffer, offset);
   pack_uint16_t(resp.rdlength, buffer, offset);

   for (int i=0; i < 4; i++) {
     memcpy(buffer + *offset, &resp.rdata[i], 1);
     *offset += 1;
   }


}

int parser_request(unsigned char *data, void *arg) {
  uint16_t flags;
  int offset = 0;

  Format *format = (Format *)arg;
  format->headclient.id = unpack_uint16_t(data, &offset);
  flags = unpack_uint16_t(data, &offset);

  format->headclient.qr = (flags >> 15)&0x1;
  format->headclient.opcode = (flags >> 11)&0xF;
//  hclient.aa = (flags >> 10)&0x1;
  format->headclient.tc = (flags >> 9)&0x1;
  format->headclient.rd = (flags >> 8)&0x1;
//  hclient.ra = (flags >> 7)&0x1;
  format->headclient.z = (flags >> 6)&0x1;
//  hclient.rcode = (flags >> 2)&0x1;
  format->headclient.ad = (flags >> 5)&0x1;
  format->headclient.nauth = (flags >> 4)&0x1;

  format->headclient.qdcount = unpack_uint16_t(data, &offset);
  format->headclient.nscount = unpack_uint16_t(data, &offset);
  format->headclient.ancount = unpack_uint16_t(data, &offset);
  format->headclient.arcount = unpack_uint16_t(data, &offset);


  if (format->headclient.qr != 0) {return FORMERR;}
  if (format->headclient.opcode < 0 || format->headclient.opcode >= 3) {return FORMERR;}
  if (format->headclient.rd != 1) {return FORMERR;}
  if (format->headclient.z != 0) {return FORMERR;}
  if (format->headclient.qdcount > 0xffff || format->headclient.qdcount < 1) {return FORMERR;}
  if (format->headclient.tc != 0) {return FORMERR;}

  for (int qdcount=format->headclient.qdcount; qdcount > 0; qdcount--) {
     uint16_t i = (format->headclient.qdcount - qdcount);
     offset = parser_name_domain(data, offset, format->question[i].qname);
     format->question[i].qtype = unpack_uint16_t(data, &offset);
     format->question[i].qclass = unpack_uint16_t(data, &offset);
  }


  if (SIMPLE_SERVER_DNS) {
    return NOERROR;
  }

  //Aqui termina el RFC 1035


  /* Extensiones de DNS del RFC 6891 */

  return NOERROR;

}


void get_request(evutil_socket_t fd, short events, void *Request_Data) {
  int type;
  int size;
  socklen_t len = sizeof(type);
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int bytes_received;

  getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len);
  size = (type == SOCK_STREAM) ? MAX_SIZE_MESSAGE_TCP : MAX_SIZE_MESSAGE_UDP;
  unsigned char data[size];
  if (type == SOCK_STREAM) { //TCP
   bytes_received = recv(fd, data, MAX_SIZE_MESSAGE_TCP, 0);
  }
  else { //UDP
   bytes_received = recvfrom(fd, data, MAX_SIZE_MESSAGE_UDP, 0, (struct sockaddr *)&client_addr, &client_len);
  }
  if (bytes_received == -1) {}

  ClientData *request_data = (ClientData *)Request_Data;
  request_data->client_address = client_addr;
  request_data->client_length = client_len;
  request_data->fd = fd;
  REQUESTSTATUS = parser_request(data, (void *)request_data->format);
}

void send_response(evutil_socket_t client, struct sockaddr_in *client_addr, socklen_t addr_len, Format *format_dns) {
  uint8_t buffer[MAX_SIZE_MESSAGE_UDP];
  size_t offset = 0;

  encoded_packet_header(format_dns->headserver, buffer, &offset);

  int size = format_dns->headserver.qdcount;
  for (int i=0; i < size; i++) {
     encoded_packet_question(format_dns->question[i], buffer, &offset);
     if (format_dns->response[i].rdlength != 0) {
        encoded_packet_response(format_dns->response[i], buffer, &offset);
     }

  }

  sendto(client, buffer, offset, 0, (struct sockaddr *)client_addr, addr_len);

}


struct event_base *ev_base;

void server_close(int server) {
  event_base_loopbreak(ev_base);
  close(server);
}


int server_conf(int family, int type, ClientData* request_data) {

  int rc;
  struct sockaddr_in self;
  struct event *ev_new;
  int SOCKET_SERVER_FD;
  SOCKET_SERVER_FD = socket(family, type, 0);
  if (SOCKET_SERVER_FD<0) {
    printf("Error al crear el socket\n");
    exit(EXIT_FAILURE);
  }
  self.sin_family = family;
  self.sin_port = htons(PORT);
  self.sin_addr.s_addr = inet_addr(ADDRESS);
  if (bind(SOCKET_SERVER_FD, (struct sockaddr *)&self, sizeof(self)) < 0) {
    perror("Error en bind");
    exit(EXIT_FAILURE);
  }

  if (type == SOCK_STREAM && listen(SOCKET_SERVER_FD, MAX_CLIENTS)) {
    printf("Error al escuchar conexiones\n");
    exit(EXIT_FAILURE);
  }

  ev_base = event_base_new();
  ev_new = event_new(ev_base, SOCKET_SERVER_FD, EV_READ | EV_PERSIST, get_request, (void *)request_data);
  event_add(ev_new, NULL);
  return SOCKET_SERVER_FD;
}



void handler_server() {

  int ev;
  int sock_server;

  ClientData *request_data = malloc(sizeof(ClientData));
  request_data->format = malloc(sizeof(Format));

  sock_server = server_conf(SOCK_DGRAM, AF_INET, (void*)request_data);
  TrieNode *root = createNode();
  insert_psl_load_file(root, psl_path_file);
  add_items();

  Format *format = request_data->format;
  printf("Server ON\nListening In -> Port: %d, Address: %s\n", PORT, ADDRESS);
  while (1) {
    uint16_t num_qdcount = 0;
    uint16_t num_ancount = 0;
    uint16_t num_nscount = 0;
    uint16_t num_arcount = 0;

    ev = event_base_loop(ev_base, EVLOOP_ONCE);
    if (ev == -1) {
      server_close(sock_server);
      break;
    }

    //RESPONSE
    for (int i=0; i < format->headclient.qdcount; i++) {
       memset(format->response[i].name, 0, sizeof(format->response[i].name));
       memcpy(format->question[i].qname + strlen((char *)format->question[i].qname), ".", 1);
       encoded_dns_format((char *)format->question[i].qname, format->response[i].name);
       format->response[i].type = format->question[i].qtype;
       format->response[i]._class = format->question[i].qclass;
       format->response[i].ttl = 0; //No almacenar en cache
       get_zone_file_address(format->response[i].rdata, format->question[i], root);
       get_size_rdata(&format->response[i].rdlength, format->response[i].rdata);
       num_ancount++;
    }

    //HEAD
    format->headserver.id = format->headclient.id;
    format->headserver.qr = 1; //response
    format->headserver.opcode = format->headclient.opcode;
    format->headserver.aa = response_authoritative();  //debuelve 1 si el nombre dns esta en la base de datos de lo contrario 0
    format->headserver.tc = truncated_bit_tc();        //debuelve 1 si la respuesta excede el maximo de bytes permitidos
    format->headserver.rd = format->headclient.rd;
    if (RECURSION_ACTIVATE) {format->headserver.ra = 1;}
    format->headserver.z = 0;
    format->headserver.rcode = REQUESTSTATUS;

    format->headserver.qdcount = format->headclient.qdcount;
    format->headserver.ancount = num_ancount;
    format->headserver.nscount = num_nscount;
    format->headserver.arcount = num_arcount;


    send_response(request_data->fd, &request_data->client_address, request_data->client_length, format);
    memset(format, 0, sizeof(Format));  //No Cache
  }
  free(request_data->format);
  free(request_data);
  freeTrie(root);

}


int main() {
  handler_server();
  return 0;

}
