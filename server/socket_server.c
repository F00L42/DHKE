#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "aes_server.h"
#include "DH.h"
#include "color.h"
#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);
void trans_msg(int sockfd, unsigned char *key);
int psk(int sockfd);

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("USAGE: ./server Port\nExample: ./server 8888");
        return 0;
    }
    int sockfd, connfd, len;
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
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) != 0)
    {
        printf("Bind Failed\n");
        exit(1);
    }

    if ((listen(sockfd, 5)) != 0)
    {
        printf("Listen Failed!\n");
        exit(1);
    }
    len = sizeof(cli);

    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0)
    {
        printf("Acccept Failed!\n");
        exit(1);
    }
    else
        printf("Connection accepted sucessfully!\n");
    printf(YELLOW"DH\n"NONE);
    mpz_t dh_s;
    mpz_init(dh_s);
    // 根据DH协议交换信息，得到密钥dh_s
    exchange_dh_key(connfd, dh_s);

    // 将密钥保存为unsigned char数组类型
    unsigned char key[32];
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("D-H Secret Key: %Zd\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s
    printf(YELLOW"AES\n"NONE);

    // 客户端服务器通信
    trans_msg(connfd, key);

    close(sockfd);
    return 0;
}

// 根据DH协议交换密钥
void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key server_dh_key;
    mpz_t client_pub_key; // 客户端公钥
    char buf[MAX];
    mpz_inits(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
              server_dh_key.pub_key, server_dh_key.s, client_pub_key, NULL);
    mpz_set_ui(server_dh_key.g, (unsigned long int)5); // g = 5
    // 从客户端接收p
    bzero(buf, MAX);
    printf("Receiving p from client...\n");
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_dh_key.p, buf + 3, 16); // 将p写入server_dh_key.p
    gmp_printf("p = %Zd\n", server_dh_key.p);

    // 生成服务器私钥
    printf("Generating Private & Public Key of the server(Press [Enter] to continue)...\n");
    generate_pri_key(server_dh_key.pri_key);
    gmp_printf("Private Key of server: %Zd\n", server_dh_key.pri_key);
    // calc the public key B of server
    mpz_powm(server_dh_key.pub_key, server_dh_key.g, server_dh_key.pri_key,
             server_dh_key.p);
    gmp_printf("Public Key of server: %Zd\n", server_dh_key.pub_key);

    // 将服务器公钥发送给客户端
    bzero(buf, MAX);
    printf("Press [Enter] to send Public Key to client...");
    getchar();
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, server_dh_key.pub_key);
    write(sockfd, buf, sizeof(buf));

    // 接收客户端公钥
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(client_pub_key, buf + 3, 16);
    //mpz_sub(client_pub_key, client_pub_key, temp); // TODO: psk
    gmp_printf("Public Key of client: %Zd\n", client_pub_key);

    // 服务器计算DH协议生成的密钥s
    printf("Press [Enter] to calculate the Common Secret Key...");
    getchar();
    mpz_powm(server_dh_key.s, client_pub_key, server_dh_key.pri_key,
             server_dh_key.p);
    mpz_set(s, server_dh_key.s);

    mpz_clears(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
               server_dh_key.pub_key, server_dh_key.s, client_pub_key, NULL);
}

// 客户端服务器发送接收加密的消息
void trans_msg(int sockfd, unsigned char key[])
{
    unsigned char text[36];
    unsigned char expansion_key[15 * 16];
    memcpy(text, "msg", 3);
    //密钥扩展，生成轮密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND);
    while (1)
    {
        bzero(text + 3, 33);
        printf("Waiting for message...\n");
        read(sockfd, text, sizeof(text));
        printf("Cipher text from client: \n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // AES256解密密文
        Contrary_AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        printf("Plain text: \n");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n");
        bzero(text + 3, 33);
        // 服务器发送
        printf("Plain text to be sent: \n");
        scanf("%s", text + 3);
        // AES256加密
        AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        printf("Cipher text:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        // 发送给客户端
        write(sockfd, text, sizeof(text));
        printf("\n\n");
    }
}
