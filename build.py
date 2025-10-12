import os

def build():
    os.system("docker compose up -d --build server")
def clangd():
    os.system("cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_SKIP_BUILD_RPATH=ON -S . -B build")
    os.system("cp -f build/compile_commands.json .")
    os.system("rm -r ./build")


if __name__ == "__main__":
    if os.path.exists('./build'):
        clangd()
        build()
    else:
        os.system('mkdir build')
        clangd()
        build()
