env = Environment()

# global settings/args
######################
if ARGUMENTS.get('debug', 0):
        env.Append( CCFLAGS = '-ggdb' )

env.Program(            target = 'diffie',
                        source = ['src/diffie.c'] )
                        
