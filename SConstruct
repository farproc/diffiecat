env = Environment()

# global settings/args
######################
if ARGUMENTS.get('debug', 0):
        env.Append( CCFLAGS = '-ggdb' )

env.Program(            target = 'diffiecat',
                        source = ['src/diffie_client.c'],
                        LIBS   = ['crypto','readline'] )

