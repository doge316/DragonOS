#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DNS_PORT 53 
#define BUF_SIZE 512 // 能容纳DNS报文的最大长度

// 构造DNS查询报文
int build_dns_query(const char *hostname, unsigned char *buf) {
    memset(buf, 0, BUF_SIZE);
    // 构造DNS报文头部
    buf[0] = 0x12; buf[1] = 0x34; // ID
    buf[2] = 0x01; // Flag=1，递归查询
    buf[5] = 0x01; // QDCOUNT=1

    // 将域名字符串转换成 标签长度+标签内容 的格式
    // 例如 "www.example.com" -> [3, 'www', 7, 'example', 3, 'com', 0]
    // 12字节头部后开始写域名
    int pos = 12;
    const char *h = hostname;
    while (*h) {
        const char *dot = strchr(h, '.');
        int len = dot ? (dot - h) : strlen(h);
        buf[pos++] = len;
        memcpy(buf + pos, h, len);
        pos += len;
        if (!dot) break;
        h = dot + 1;
    }
    buf[pos++] = 0; // 结尾
    buf[pos++] = 0; buf[pos++] = 1; // QTYPE=A
    buf[pos++] = 0; buf[pos++] = 1; // QCLASS=IN
    return pos; // 返回报文长度
}

// 解析DNS响应
void parse_dns_response(unsigned char *buf, int len) {
    int qdcount = (buf[4] << 8) | buf[5]; // 问题数(1)
    int ancount = (buf[6] << 8) | buf[7]; 
    int pos = 12;
    // 跳过问题部分
    for (int i = 0; i < qdcount; i++) {  
        while (buf[pos] != 0) pos += buf[pos] + 1;
        pos += 5; // 跳过类型（2字节）和类（2字节）以及结尾的0
    }
    // 解析回答部分
    for (int i = 0; i < ancount; i++) {
        if ((buf[pos] & 0xC0) == 0xC0) pos += 2; // name指针
        else while (buf[pos] != 0) pos += buf[pos] + 1, pos++;
        int type = (buf[pos] << 8) | buf[pos+1];
        pos += 8;
        int rdlen = (buf[pos] << 8) | buf[pos+1];
        pos += 2;
        if (type == 1 && rdlen == 4) { // A记录
            printf("%d.%d.%d.%d\n", buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
        }
        pos += rdlen;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <域名>\n", argv[0]);
        return 1;
    }
    unsigned char buf[BUF_SIZE];
    int query_len = build_dns_query(argv[1], buf);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    sendto(sock, buf, query_len, 0, (struct sockaddr*)&addr, sizeof(addr));
    int n = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
    if (n > 0) {
        parse_dns_response(buf, n);
    } else {
        printf("查询失败\n");
    }
    close(sock);
    return 0;
}