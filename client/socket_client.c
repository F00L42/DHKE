#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "aes_client.h"
#include "DH.h"
#include "color.h"

#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);
void trans_msg(int sockfd, unsigned char *key);
void psk(int sockfd);

int main(int argc, char **argv)
{
    if (3 != argc)
    {
        printf("USAGE: ./client ServerIP ServerPort\nExample: ./client 127.0.0.1 8888\n");
        return 0;
    }
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Socket Failed!\n");
        exit(1);
    }
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    // connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Server connection faild!\n");
        exit(1);
    }
    else
        printf("Server connectted successfully!\n");
    printf(YELLOW"DH\n"NONE);
    mpz_t dh_s;
    mpz_init(dh_s);
    exchange_dh_key(sockfd, dh_s);

    // 声明AES加密解密及通信所需要的变量
    unsigned char key[33];
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("D-H Secret Key: %Zd\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s
    printf(YELLOW"AES\n"NONE);

    trans_msg(sockfd, key);

    return 0;
}

// 通过Diffie Hellman协议商讨出一个密钥s
void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key client_dh_key; // 客户端生成的密钥
    mpz_t server_pub_key; // 服务器公钥
    char buf[MAX];
    // 初始化mpz_t类型的变量
    mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
              client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
    printf("Generating large prime p(Press [Enter] to continue)...");
    getchar();
    generate_p(client_dh_key.p);
    gmp_printf("p = %Zd\n", client_dh_key.p);
    mpz_set_ui(client_dh_key.g, (unsigned long int)5); // base g = 5
    // 将p发送给服务器
    bzero(buf, MAX);
    memcpy(buf, "pri", 3);
    mpz_get_str(buf + 3, 16, client_dh_key.p);
    write(sockfd, buf, sizeof(buf));

    // 生成客户端的私钥a
    printf("Generating Private & Public Key of the client(Press [Enter] to continue)...");
    getchar();
    generate_pri_key(client_dh_key.pri_key);
    gmp_printf("Private Key of the client: %Zd\n", client_dh_key.pri_key);

    // 计算客户端的公钥A
    mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
             client_dh_key.p);
    gmp_printf("Public Key of the client: %Zd\n", client_dh_key.pub_key);
    
    // 接收服务器的公钥B
    bzero(buf, MAX);
    printf("Waiting for Public Key of the server, sending Public Key of the client...\n");
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key
    gmp_printf("Public Key of the server: %Zd\n", server_pub_key);

    // 将客户端公钥发送给服务器
    bzero(buf, MAX);
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, client_dh_key.pub_key); // 按16进制将公钥传递给buf
    write(sockfd, buf, sizeof(buf));

    // 客户端计算DH协议得到的密钥s
    printf("Press [Enter] to calculate the Common Secret Key...");
    getchar();
    mpz_powm(client_dh_key.s, server_pub_key, client_dh_key.pri_key,
             client_dh_key.p);
    mpz_set(s, client_dh_key.s); // 将密钥传递给s

    // 清除mpz_t变量
    mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
               client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
}

// 客户端服务器发送接收加密后的消息
void trans_msg(int sockfd, unsigned char key[])
{
    unsigned char text[36];
    unsigned char expansion_key[15 * 16];
    memcpy(text, "msg", 3); // 标识消息头
    // 密钥扩展，生成轮密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND);
    printf("Round Key initialized sucessfully!\n");
    while (1)
    {
        // 输入要发送的明文
        bzero(text + 3, 33);
        printf("Plain text to be sent:\n");
        scanf("%s", text + 3);
        // AES256加密
        AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        printf("Cipher text:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // 发送密文
        write(sockfd, text, sizeof(text));
        printf("Sent sucessfully！\nWaiting for reply...\n");
        // 接收服务器发送的密文
        bzero(text + 3, 33);
        read(sockfd, text, sizeof(text));
        printf("Cipher text from server:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // AES256解密
        Contrary_AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        printf("Plain text:\n");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n\n");
    }
}