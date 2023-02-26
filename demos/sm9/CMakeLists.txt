cmake_minimum_required(VERSION 3.0)
project(sm9demo)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(sm9_sign_demo sm9_sign_demo.c)
# add_executable(sm3_hmac_demo sm3_hmac_demo.c)
# add_executable(sm3_kdf_demo sm3_kdf_demo.c)
target_link_libraries(sm9_sign_demo gmssl)
# target_link_libraries(sm3_hmac_demo gmssl)
# target_link_libraries(sm3_kdf_demo gmssl)
