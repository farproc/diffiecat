env = Environment()

# global settings/args
######################
if ARGUMENTS.get('debug', 0):
        env.Append( CCFLAGS = '-ggdb' )

#env.Program(            target = 'diffie',
#                        source = ['src/diffie.c'] )

#env.Program(            target = 'opendiffie',
#                        source = ['src/openssl_diffie.c'],
#                        LIBS   = ['crypto'] )

env.Program(            target = 'diffieclient',
                        source = ['src/diffie_client.c'],
                        LIBS   = ['crypto','readline'] )

