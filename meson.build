project(
    'ThrottleStopPoC', 
    'c',
    default_options: [
        'warning_level=3',
        'c_std=c11',
        'buildtype=release',
        'strip=true' 
    ]
)

sources = files(
    'src/EProcess.c',
    'src/Exploit.c',
    'src/Main.c',
    'src/vtop.c'
)

executable(
    'ThrottleStopPoC', 
    sources,
    include_directories: include_directories('src/')
)