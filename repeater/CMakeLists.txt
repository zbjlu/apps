cmake_minimum_required(VERSION 3.8)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/shell.c)
target_sources(app PRIVATE src/test.c)

include_directories($ENV{ZEPHYR_BASE}/ext/hal/unisoc/)

target_sources_ifdef(
  CONFIG_BT_UWP5661
  app PRIVATE
  src/bluetooth/blues.c
  src/bluetooth/throughput.c
  )

#target_sources_ifdef(
#  CONFIG_WIFIMGR
#  app PRIVATE
#  src/bluetooth/wifi_manager_service.c
#  )

target_sources_ifdef(
  CONFIG_FLASH_TEST
  app PRIVATE
  src/sfc/sfc_flash_test.c
  )

target_sources_ifdef(
  CONFIG_OTA
  app PRIVATE
  src/ota/ota_shell.c
  )

target_sources_ifdef(
  CONFIG_ZPERF
  app PRIVATE
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/shell_utils.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_tcp_receiver.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_udp_receiver.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_session.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_shell.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_tcp_uploader.c
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src/zperf_udp_uploader.c
  )

# include files zperf needs
target_include_directories(app PRIVATE
  $ENV{ZEPHYR_BASE}/subsys/net/ip
  )

# include files zperf needs
target_include_directories(app PRIVATE
  $ENV{ZEPHYR_BASE}/samples/net/zperf/src
  )

add_subdirectory_ifdef(CONFIG_DHRYSTONE	dhrystone)
add_subdirectory_ifdef(CONFIG_ENGPC	engpc)
add_subdirectory_ifdef(CONFIG_IWNPI	iwnpi)
add_subdirectory_ifdef(CONFIG_BT_TEST	bt_test)
