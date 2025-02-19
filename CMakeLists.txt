cmake_minimum_required(VERSION 3.28)
project(schnorr)
# 设置使用的c++版本号
set(CMAKE_CXX_STANDARD 20)
# 将CmakeLists.txt所在目录下的所有cpp文件搜索出来，并将其存储到变量SRC中
file(GLOB SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
# 将该工程的源代码编译为可执行文件
add_executable(schnorr ${SRC})
# 指定头文件所在的目录,这里指定了两个路径(libsh/ 和 include/)
target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_include_directories(${PROJECT_NAME} PUBLIC libsh/)
# 链接静态库文件
target_link_libraries(schnorr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libs/core.a)
