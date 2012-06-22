#include <openssl/dh.h>
#include <openssl/engine.h>

#define DIFFIE_BIT_LENGTH       ( 1024 )
#define DIFFIE_GENERATOR        ( DH_GENERATOR_5 )

int main( int argc, char *argv[] )
{
    int     nRetVal     = EXIT_SUCCESS;
    DH     *pAlice      = NULL,
           *pBob        = NULL;
    int     nPrime      = 0,
            nGenerator  = 0;
    int     nPKCSLen    = 0;
    char*   pPKCSBuf    = NULL;

    int     nSharedKeyAlice = 0;
    int     nSharedKeyBob   = 0;
    char*   pSharedKeyAlice = NULL;
    char*   pSharedKeyBob   = NULL;

    nPrime      = DIFFIE_BIT_LENGTH;
    nGenerator  = DIFFIE_GENERATOR;

    printf( "[i]\tgenerating Alice's DH structures.\n" );
    pAlice = DH_generate_parameters( nPrime, nGenerator, NULL, NULL );
    printf( "[i]\tdone.\n" );

    // generates p & g

    printf( "[i]\tgenerating key\n" );
    DH_generate_key( pAlice );
    printf( "[i]\tdone.\n" );

    // we now have public and private keys
    
    // encode them to forward to bob
    pBob     = DH_new();
    nPKCSLen = i2d_DHparams( pAlice, &pPKCSBuf );
    if( nPKCSLen && pPKCSBuf )
    {
        pBob = d2i_DHparams( &pBob, &pPKCSBuf, nPKCSLen );
    }

    if( pBob )
    {
            // pBob has p & g. but no pub yet
            DH_generate_key( pBob );
            // bob now has pub and private keys
    }

    if( pAlice && pAlice->pub_key )
    {
            printf( "[i]\talice's public key: %s\n", BN_bn2hex( pAlice->pub_key ) );
    }
    if( pBob && pBob->pub_key )
    {
            printf( "[i]\tbob's public key: %s\n", BN_bn2hex( pBob->pub_key ) );
    }

    if( pAlice && pBob )
    {
            // alice is going to calculate the shared secret
            nSharedKeyAlice = DH_size( pAlice );
            pSharedKeyAlice = OPENSSL_malloc( nSharedKeyAlice );
            if( pSharedKeyAlice )
            {
                    DH_compute_key( pSharedKeyAlice, pBob->pub_key, pAlice );
            }

            // bob is going to do the same
            nSharedKeyBob   = DH_size( pBob );
            pSharedKeyBob   = OPENSSL_malloc( nSharedKeyBob );
            if( pSharedKeyBob )
            {
                    DH_compute_key( pSharedKeyBob, pAlice->pub_key, pBob );
            }

            if( pSharedKeyAlice && pSharedKeyBob && nSharedKeyAlice == nSharedKeyBob )
            {
                    printf( "[i] shared key length: %d\n", nSharedKeyBob );
                    if( 0 == memcmp( pSharedKeyAlice, pSharedKeyBob, nSharedKeyBob ) )
                    {
                            printf( "[i]\tshared keys match\n" );
                    } else {
                            printf( "[i]\tshared keys DON\'T  match\n" );
                    }
            }
    }
    

    // int DH_size(const DH *dh); 
    // int DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
    //
    // key should be DH_size long



    /*
    printf( "[i]\tGenerating Bob's DH structures.\n" );
    pBob   = DH_generate_parameters( nPrime, nGenerator, NULL, NULL );
    */


    if( pAlice )
    {
            DH_free( pAlice );
            pAlice = NULL;
    }
    if( pPKCSBuf )
    {
            // OPENSSL_free( pPKCSBuf ); --- don't know how to free this?!!
            pPKCSBuf = NULL;
    }
    if( pBob )
    {
            DH_free( pBob );
            pBob   = NULL;
    }


    return nRetVal;
}
