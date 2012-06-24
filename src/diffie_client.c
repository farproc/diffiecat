#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

// crypto
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

// readline
#include <readline/history.h>
#include <readline/readline.h>

typedef struct args_t
{
    bool        bServer;
    uint16_t    nPort;
    uint32_t    nAddress;
} ARGS;

bool parseArgs( ARGS *pArg, int argc, char *argv[] )
{
    bool    bRetVal = false;
    int     i       = 0;
    char   *pPtr    = NULL;

    if( pArg && 3 == argc && argv )
    {
            if(        0 == strcmp( argv[1], "-client" ) )
            {
                // client
                pArg->bServer   = false;
                pPtr            = strtok( argv[2], ":" );
                pArg->nAddress  = inet_addr( pPtr );
                pPtr            = strtok( NULL, ":" );
                pArg->nPort     = atoi( pPtr );
                bRetVal         = true;
            } else if( 0 == strcmp( argv[1], "-server" ) )
            {
                // server
                pArg->bServer   = true;
                pArg->nPort     = atoi( argv[2] );
                bRetVal         = true;
            }
    }
    return bRetVal;
}

int getNetworkConnection( ARGS *pArgs )
{
        int                 nRetVal     = -1,
                            nClientSock =  0,
                            clilen      =  0;
        struct sockaddr_in  serv_addr   = { 0 },
                            cli_addr    = { 0 };

        if( pArgs )
        {
            // default to a server setup
            serv_addr.sin_family        = AF_INET;
            serv_addr.sin_port          = htons( pArgs->nPort );
            serv_addr.sin_addr.s_addr   = INADDR_ANY;
            nRetVal                     = socket( PF_INET, SOCK_STREAM, 0 );

            if( pArgs->bServer )
            {
                // TODO: check your return values!
                bind( nRetVal, (struct sockaddr *) &serv_addr, sizeof(serv_addr) );
                listen( nRetVal, 5 );

                // accept loop
                while( true )
                {
                    clilen = sizeof(cli_addr);

                    printf( "[i]\twaiting for connection......" );
                    fflush( stdout );

                    nClientSock = accept( nRetVal, (struct sockaddr *) &cli_addr, &clilen);

                    printf( "got one.\n" );

                    if( 0 == fork() )
                    {
                        // child
                        nRetVal = nClientSock;
                        break;
                    } else {
                        // parent - accept more connections
                    }
                }
            } else {
                // we're use cli instead of serv as it reads better
                cli_addr                = serv_addr;
                cli_addr.sin_addr.s_addr= pArgs->nAddress;
                
                // TODO: more unchecked return values
                connect( nRetVal, (struct sockaddr *) &cli_addr, sizeof( cli_addr ) );
            }
        }

        return nRetVal;
}

char *stripwhite( char *string )
{
    char    *s  = NULL,
            *t  = NULL;

  for(s = string; isspace(*s); s++);
    
  if(*s == '\0')
    return s;

  t = s + strlen(s) - 1;

  while( t > s && isspace (*t) )
  {
    t--;
  }

  *++t = '\0';

  return s;
}

int enterCommandLoop( int s, char *pKey, int nKeyLen )
{
    int         nRetVal = EXIT_FAILURE; 
    AES_KEY     sKey    = { 0 };
    char        pPlain[  AES_BLOCK_SIZE ] = { 0 };
    char        pCipher[ AES_BLOCK_SIZE ] = { 0 };

    if( pKey && nKeyLen )
    {
        // use the same key in both directions
        AES_set_encrypt_key( pKey, nKeyLen * 8, &sKey );
        AES_set_decrypt_key( pKey, nKeyLen * 8, &sKey );

        rl_initialize();

        while( true )
        {
            char *line = readline(">");
            char *ptr  = line;
            int   len  = 0;

            if( line )
            {
                line = stripwhite( line );
                len  = strlen( line );

                add_history( line );

                while( len )
                {
                    bzero( pPlain,  AES_BLOCK_SIZE );
                    bzero( pCipher, AES_BLOCK_SIZE );

                    // fill the block with data
                    memcpy( pPlain, ptr, ( len > AES_BLOCK_SIZE ) ? AES_BLOCK_SIZE : len );

                    // work the AES magic
                    AES_encrypt( pPlain, pCipher, &sKey );

                    // send it on its way
                    write( s, pCipher, AES_BLOCK_SIZE );
                    printf( "[i]\tsent.\n" );

                    if( len > AES_BLOCK_SIZE )
                    {
                        len -= AES_BLOCK_SIZE;
                        ptr += AES_BLOCK_SIZE;
                    } else {
                        len  = 0;
                    }
                }

                // send encrypted NULLs (end-of-message)
                bzero( pPlain,  AES_BLOCK_SIZE );
                bzero( pCipher, AES_BLOCK_SIZE );
                AES_encrypt( pPlain, pCipher, &sKey );
                write( s, pCipher, AES_BLOCK_SIZE );

                printf( "[i]\tsent entire message.\n" );

            } else {
                printf( "[i]\tquiting...\n" );
                break;
            }
        }
    }

    return nRetVal;
}

int main( int argc, char *argv[] )
{
    int     nRetVal     = EXIT_SUCCESS;
    DH     *pMine       = NULL,
           *pTheirs     = NULL;

    int     nSharedKey  = 0;
    char*   pSharedKey  = NULL;

    char    pFoldedKey[ SHA256_DIGEST_LENGTH ] = { 0 };

    ARGS    sArgs       = { 0 };
    int     fdSock      = 0;


    if( !parseArgs( &sArgs, argc, argv ) )
    {
            printf( "usage:\n%s\n"
                            "\t-client <ip>:<port>\n"
                            "\t-server <port>\n",
                            argv[0] );
            return EXIT_FAILURE;
    }

    // bind/connect
    fdSock = getNetworkConnection( &sArgs );

    printf( "[i]\tgot a connection\n" );

    // create diffie structures
    pMine   = DH_new();
    pTheirs = DH_new();
    if( pMine && pTheirs )
    {
        BN_hex2bn( &(pMine->p),
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
            "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
            "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
            "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
            "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
            "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
            "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
            "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
            "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
            "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
            "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
            "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
            "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
            "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
            "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
            "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
            "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
            "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
            "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
            "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
            "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
            "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
            "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
            "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
            "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
            "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
            "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
            "60C980DD98EDD3DFFFFFFFFFFFFFFFFF" );
        BN_hex2bn( &(pMine->g), "2" );
        // reuse the bignums
        pTheirs->p = BN_dup( pMine->p );
        pTheirs->g = BN_dup( pMine->g );
    }
    // pMine has p & g

    if( pMine )
    {
        fprintf( stdout, "[i]\tgenerating key....." );
        fflush( stdout );
        DH_generate_key( pMine );
        fprintf( stdout, "done.\n" );
    } else {
        fprintf( stdout, "[x]\tfailed to generate key.\n" );
        return EXIT_FAILURE;
    }

    //
    // we now have public and private keys
    //


    //
    // now push our public key
    //
    pSharedKey = BN_bn2hex( pMine->pub_key ); // ( just reusing the var )
    nSharedKey = strlen( pSharedKey );
    printf( "[i]\tsending public key (%d)\n", nSharedKey );
    write( fdSock, pSharedKey, nSharedKey );

    //
    // read in pTheirs public key
    //
    bzero( pSharedKey, nSharedKey );
    read( fdSock, pSharedKey, nSharedKey );

    //
    // parse in the public key
    //
    BN_hex2bn( &(pTheirs->pub_key), pSharedKey );

    //
    // free that temp buffer
    //
    OPENSSL_free( pSharedKey );
    pSharedKey = NULL;
    nSharedKey = 0;

    //
    // calculate shared key
    //
    nSharedKey = DH_size( pMine );
    pSharedKey = OPENSSL_malloc( nSharedKey );
    if( pSharedKey )
    {
            DH_compute_key( pSharedKey, pTheirs->pub_key, pMine );
    }

    if( nSharedKey && pSharedKey )
    {
            // key is too big - needs folding
            SHA256_CTX      ctx                         =   { 0 };

            SHA256_Init( &ctx );
            SHA256_Update( &ctx, pSharedKey, nSharedKey );
            SHA256_Final( pFoldedKey, &ctx );

            fprintf( stdout, "[i]\tsuccesfully key-exchanged.\n" );

            {
                BIGNUM *pOutput = BN_bin2bn( pFoldedKey, sizeof( pFoldedKey ), NULL );
                char   *pTextOut= BN_bn2hex( pOutput );
                fprintf( stdout, "[i]\tshared key:\n%s\n", pTextOut );

                OPENSSL_free( pTextOut );
                BN_free( pOutput );
            }


            nRetVal = enterCommandLoop( fdSock, pFoldedKey, sizeof( pFoldedKey ) );

            close( fdSock );
    }


    if( pMine )
    {
            DH_free( pMine );
            pMine = NULL;
    }
    if( pTheirs )
    {
            DH_free( pTheirs );
            pTheirs = NULL;
    }


    return nRetVal;
}
