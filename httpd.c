/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))
#define S_IFMT __S_IFMT
#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2
#define u_short unsigned short
void accept_request(void *);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
// GET / HTTP/1.1
// Host: 192.168.0.23:47310
// Connection: keep-alive
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*; q = 0.8
// Accept - Encoding: gzip, deflate, sdch
// Accept - Language : zh - CN, zh; q = 0.8
// Cookie: __guid = 179317988.1576506943281708800.1510107225903.8862; monitor_count = 5
//
 
// POST / color1.cgi HTTP / 1.1
// Host: 192.168.0.23 : 47310
// Connection : keep - alive
// Content - Length : 10
// Cache - Control : max - age = 0
// Origin : http ://192.168.0.23:40786
// Upgrade - Insecure - Requests : 1
// User - Agent : Mozilla / 5.0 (Windows NT 6.1; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 55.0.2883.87 Safari / 537.36
// Content - Type : application / x - www - form - urlencoded
// Accept : text / html, application / xhtml + xml, application / xml; q = 0.9, image / webp, */*;q=0.8
// Referer: http://192.168.0.23:47310/
// Accept-Encoding: gzip, deflate
// Accept-Language: zh-CN,zh;q=0.8
// Cookie: __guid=179317988.1576506943281708800.1510107225903.8862; monitor_count=281
// Form Data
// color=gray
void accept_request(void *arg)
{
    int client = (intptr_t)arg; //连接端口
    char buf[1024];
    size_t numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    char *query_string = NULL;
    //根据上面的Get请求，可以看到这边就是取第一行
    //这边都是在处理第一条http信息
    //"GET / HTTP/1.1\n"    
    numchars = get_line(client, buf, sizeof(buf));
    i = 0; j = 0;

    //ISspace检查参数是否为空格。即最多读取255个字符，直到空格为止
    //根据http请求的格式，method里的内容是http请求的请求类型，GET或POST
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';

    //strcasecmp是忽略大小写的比较
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client);//tinyhttp仅仅实现了GET和POST 发送501说明相应方法没有实现
        return;
    }

    //cgi为标志位，置1说明开启cgi解析
    //如果请求方法为POST，需要cgi解析
    if (strcasecmp(method, "POST") == 0)
        cgi = 1;

    //跳过空格
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    
    //得到 "/"   注意：如果你的http的网址为http://192.168.0.23:47310/index.html
    //               那么你得到的第一条http信息为GET /index.html HTTP/1.1，那么
    //               解析得到的就是/index.html,存在url[]

    i = 0;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';
    //如果是GET请求，url可能会带有?,有查询参数，query_string 指针指向 url 中 ？ 后面的 GET 参数
    //如   http://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&tn=baidu
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        //如果带有查询参数，需要执行cgi，解析参数，设置标志位为1
        if (*query_string == '?')
        {
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
    }
    //以上已经将起始行解析完毕
    //url中的路径格式化到path，在 tinyhttpd 中服务器文件是在 htdocs 文件夹下
    sprintf(path, "htdocs%s", url);

    //默认地址，解析到的路径如果为/，即如果path只是一个目录，默认为访问首页index.html
    if (path[strlen(path) - 1] == '/')
        strcat(path, "index.html");

    //函数定义:    int stat(const char *file_name, struct stat *buf);
    //函数说明:    通过文件名filename获取文件信息，并保存在buf所指的结构体stat中
    //返回值：     执行成功则返回0，失败返回-1，错误代码存于errno（需要include <errno.h>）
    if (stat(path, &st) == -1) {
        //假如访问的网页不存在或打开失败，则不断的读取剩下的header信息并丢弃
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);//发送404错误信息
    }
    else
    {   
        //如果是目录，继续拼接
        if ((st.st_mode & __S_IFMT) == __S_IFDIR)
            strcat(path, "/index.html");
        //如果你的文件默认是有执行权限的，将cgi置1，自动解析成cgi程序，如果有执行权限但是不能执行，会接受到报错信号
        //S_IXUSR:文件所有者具可执行权限
        //S_IXGRP:用户组具可执行权限
        //S_IXOTH:其他用户具可读取权限  
        if ((st.st_mode & S_IXUSR) ||
                (st.st_mode & S_IXGRP) ||
                (st.st_mode & S_IXOTH)    )
            cgi = 1;
        if (!cgi)
            serve_file(client, path);//接读取文件返回给请求的http客户端
        else
            execute_cgi(client, path, method, query_string);//执行cgi文件
    }

    close(client);//关闭socket
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
//400错误
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
//读取服务器上某个文件写到 socket 套接字。
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
//主要处理发生在执行 cgi 程序时出现的错误。
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system cazhierrors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];   //缓存区
    //两个管道
    int cgi_output[2];
    int cgi_input[2];

    pid_t pid;
    int status;

    int i;
    char c;
    //读取的字符数
    int numchars = 1;
    //http的content_length
    int content_length = -1;

    //默认字符?不懂
    buf[0] = 'A'; buf[1] = '\0';

    // GET / HTTP/1.1
    // Host: 192.168.0.23:47310
    // Connection: keep-alive
    // Upgrade-Insecure-Requests: 1
    // User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36
    // Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*; q = 0.8
    // Accept - Encoding: gzip, deflate, sdch
    // Accept - Language : zh - CN, zh; q = 0.8
    // Cookie: __guid = 179317988.1576506943281708800.1510107225903.8862; monitor_count = 5
    //
    
    // POST / color1.cgi HTTP / 1.1
    // Host: 192.168.0.23 : 47310
    // Connection : keep - alive
    // Content - Length : 10
    // Cache - Control : max - age = 0
    // Origin : http ://192.168.0.23:40786
    // Upgrade - Insecure - Requests : 1
    // User - Agent : Mozilla / 5.0 (Windows NT 6.1; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 55.0.2883.87 Safari / 537.36
    // Content - Type : application / x - www - form - urlencoded
    // Accept : text / html, application / xhtml + xml, application / xml; q = 0.9, image / webp, */*;q=0.8
    // Referer: http://192.168.0.23:47310/
    // Accept-Encoding: gzip, deflate
    // Accept-Language: zh-CN,zh;q=0.8
    // Cookie: __guid=179317988.1576506943281708800.1510107225903.8862; monitor_count=281
    // Form Data
    // color=gray

    //忽略大小写比较字符串
    if (strcasecmp(method, "GET") == 0)
        //读取数据，把整个header都读掉，因为Get写死了直接读取index.html，没有必要分析余下的http信息了
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        
        while ((numchars > 0) && strcmp("\n", buf))
        {
            //如果是POST请求，就需要得到Content-Length，Content-Length：这个字符串一共长为15位，所以
            //取出头部一句后，将第16位设置结束符，进行比较
            //第16位置为结束
            //Content-Length: 10,即目标文档长度为10
            //将header取完并丢弃
            buf[15] = '\0';//目的是为了截取Content-Length:
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }
    else/*HEAD or other*/
    {
    }

    //返回正确响应码200
    //sprintf(buf, "HTTP/1.0 200 OK\r\n");
    //send(client, buf, strlen(buf), 0);


    //#include<unistd.h>
    //int pipe(int filedes[2]);
    //返回值：成功，返回0，否则返回-1。参数数组包含pipe使用的两个文件的描述符。fd[0]:读管道，fd[1]:写管道。
    //必须在fork()前调用pipe()，否则子进程不会继承文件描述符。
    //两个进程不共享祖先进程，就不能使用pipe。但是可以使用命名管道。
    //pipe(cgi_output)执行成功后，cgi_output[0]:读通道 cgi_output[1]:写通道，这就是为什么说不要被名称所迷惑

//1. 父进程调用pipe开辟管道，得到两个文件描述符指向管道的两端。
//2. 父进程调用fork创建子进程，那么子进程也有两个文件描述符指向同一管道。
//3. 父进程关闭管道读端，子进程关闭管道写端。父进程可以往管道里写，子进程可以从管道里读，管道是用环形队列实现的，数据从写端流入从读端流出，这样就实现了进程间通信。 

    //建立管道
    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    //       fork后管道都复制了一份，都是一样的
    //       子进程关闭2个无用的端口，避免浪费             
    //       ×<------------------------->1    output
    //       0<-------------------------->×   input 
    
    //       父进程关闭2个无用的端口，避免浪费             
    //       0<-------------------------->×   output
    //       ×<------------------------->1    input
    //       此时父子进程已经可以通信

    //fork进程，子进程用于执行CGI
    //父进程用于收数据以及发送子进程处理的回复数据
    if ( (pid = fork()) < 0 ) {
        cannot_execute(client);
        return;
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    if (pid == 0)  /* child: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];
        //子进程输出重定向到output管道的1端
        dup2(cgi_output[1], STDOUT);
        //子进程输入重定向到input管道的0端
        dup2(cgi_input[0], STDIN);
        //子进程关闭两个无用端口
        close(cgi_output[0]);
        close(cgi_input[1]);
        //CGI标准需要将请求的方法存储环境变量中，然后和cgi脚本进行交互
        //存储REQUEST_METHOD
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        // 表头文件#include<unistd.h>
        // 定义函数
        // int execl(const char * path,const char * arg,....);
        // 函数说明
        // execl()用来执行参数path字符串所代表的文件路径，接下来的参数代表执行该文件时传递过去的argv(0)、argv[1]……，最后一个参数必须用空指针(NULL)作结束。
        // 返回值
        // 如果执行成功则函数不会返回，执行失败则直接返回-1，失败原因存于errno中。
        execl(path, NULL);
        exit(0);
    } else {    /* parent */
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                //开始读取POST中的内容
                recv(client, &c, 1, 0);
                //将数据发送给cgi脚本
                write(cgi_input[1], &c, 1);
            }
        //读取cgi脚本返回数据
        while (read(cgi_output[0], &c, 1) > 0)
            //发送给浏览器
            send(client, &c, 1, 0);

        close(cgi_output[0]);
        close(cgi_input[1]);
        //定义函数：pid_t waitpid(pid_t pid, int * status, int options);
        //函数说明：waitpid()会暂时停止目前进程的执行, 直到有信号来到或子进程结束.
        //如果在调用wait()时子进程已经结束, 则wait()会立即返回子进程结束状态值. 子进程的结束状态值会由参数status 返回,
        //而子进程的进程识别码也会一快返回.
        //如果不在意结束状态值, 则参数status 可以设成NULL. 参数pid 为欲等待的子进程识别码, 其他数值意义如下：
        //1、pid<-1 等待进程组识别码为pid 绝对值的任何子进程.
        //2、pid=-1 等待任何子进程, 相当于wait().
        //3、pid=0 等待进程组识别码与目前进程相同的任何子进程.
        //4、pid>0 等待任何子进程识别码为pid 的子进程.
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
//读取套接字的一行，把回车换行等情况都统一为换行符\n结束。 
//得到一行数据,只要发现c为\n,就认为是一行结束，如果读到\r,再用MSG_PEEK的方式读入一个字符(查看读取，读完不丢弃)
//如果是\n，从socket用读出如果是下个字符则不处理，将c置为\n，结束。
//如果读到的数据为0中断，或者小于0，也视为结束，c置为\n
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                //MSG_PEEK表示查看读取，读完不丢弃
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
//发送http的headers，200表示请求成功
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;  /* could use filename to determine file type */

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
//如果不是CGI文件，直接读取文件返回给请求的http客户端
void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A'; buf[1] = '\0';                        //这个赋值不清楚是干什么的
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));//将HTTP请求头读取并丢弃
    //fopen是打开一个标准I/O流
    resource = fopen(filename, "r");
    if (resource == NULL)
        not_found(client);
    else
    {
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
//port指向4000端口
int startup(u_short *port)
{
    int httpd = 0;
    int on = 1;
    struct sockaddr_in name;
    //TCP模式
    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        error_die("socket");

    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);

    //允许重用本地地址
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)  
    {  
        error_die("setsockopt failed");
    }
    //绑定socket与端口
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
    //若是随机绑定端口则将该端口赋值给port
    if (*port == 0)  /* if dynamically allocating a port */
    {
        socklen_t namelen = sizeof(name);
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
            error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
    if (listen(httpd, 5) < 0)
        error_die("listen");
    return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];
    //发送501说明相应方法没有实现
    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
    int server_sock = -1;
    u_short port = 4000;
    int client_sock = -1;
    struct sockaddr_in client_name;
    socklen_t  client_name_len = sizeof(client_name);
    pthread_t newthread;

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        client_sock = accept(server_sock,
                (struct sockaddr *)&client_name,
                &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        /* accept_request(&client_sock); */
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)//long型 4位字节 与指针一样
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
