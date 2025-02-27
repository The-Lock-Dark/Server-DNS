#define MAX_ITEMS 100
#define MAX_AMOUNT_SPOT 126


typedef struct {
  int key;
  char value[50];  //256
} KeyValuePairs;
typedef struct {
  KeyValuePairs pairs[MAX_ITEMS];
  int size;
}Dictionary;


void add_item(Dictionary* dict, int key, const char *value) {
  for (int i=0; i < dict->size; i++) {
    if (dict->pairs[i].key == key) {   //Value Exists
      return;
    }
  }

  if (dict->size < MAX_ITEMS) {
    dict->pairs[dict->size].key = key;
    strcpy(dict->pairs[dict->size].value, value);
    dict->size++;
  }
}

void free_dict(Dictionary dict) {
}

int item_exists(Dictionary* dict, int key) {
  for (int i=0; i < dict->size; i++) {
    if (dict->pairs[i].key == key) {
      return 0;
    }
  }
  return -1;
}

char *get_value(Dictionary* dict, int key) {
  for (int i=0; i < dict->size; i++) {
    if (dict->pairs[i].key == key) {
      return dict->pairs[i].value;
    }
  }
  return "";
}

void pack_addr(uint8_t *buff_addr, char *address) {
  int j = 0;
  char *piece;

  piece = strtok(address, ".");
  while (piece != NULL) {
     buff_addr[j++] = atoi(piece);
     piece = strtok(NULL, ".");
  }
}

void encoded_dns_format(const char *hostname, unsigned char *buffer) {
    int length = strlen(hostname);
    int i, j = 0, label_length = 0;

    for (i = 0; i < length; i++) {
        if (hostname[i] == '.') {
            buffer[j - label_length - 1] = label_length;
            label_length = 0;
        } else {
            if (label_length == 0) j++;
            buffer[j++] = hostname[i];
            label_length++;
        }
    }
    buffer[j] = 0;
}

size_t get_name_length(unsigned char *name, size_t max_size) {
    size_t length = 0;
    while (length < max_size && name[length] != 0) {
        length++;
    }
    return length + 1;  // Sumar 1 para incluir el terminador `00`
}


size_t len(int *obj) {
  size_t length = 0;
  while (obj[length] != 0 && !(obj[length] < 0)) {
    length++;
  }
  return length;
}

int parser_name_domain(const uint8_t *data, int offset, unsigned char *name) {
  int i = 0, length = 0;
  while (data[offset] != 0) {
    length = data[offset];
    offset++;
    for (int j = 0; j < length; j++) {
      name[i++] = data[offset++];
    }
    name[i++] = '.';
  }
  name[i - 1] = '\0';
  return offset + 1;
}

int startswith(char src[], char text[]) {
  size_t size_str_text = strlen(text);
  for (int i=0; i<size_str_text; i++) {
    if (src[i] != text[i]) {
      return -1;
    }
  }
  return 0;
}
