#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "lwip/sys.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "pcap.h"

// #include <inttypes.h>
void sniffer_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{

    wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    uint32_t length = ppkt->rx_ctrl.sig_mode ? ppkt->rx_ctrl.HT_length : ppkt->rx_ctrl.legacy_length;
    if(type == WIFI_PKT_MGMT) length -= 4;
    uint32_t now = sys_now();
    pcap_capture_packet(ppkt->payload, length, now / 1000000U, now % 1000000U);
}

void wifi_init(void)
{
    nvs_flash_init();
    tcpip_adapter_init();
    
    esp_event_loop_init(NULL, NULL);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();


    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    wifi_promiscuous_filter_t wifi_filter;
    wifi_filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&wifi_filter);
    esp_wifi_set_channel(CONFIG_SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_handler);
    esp_wifi_set_promiscuous_data_len(512);
    esp_wifi_set_promiscuous(true);

    
    // vTaskDelay( 2500 / portTICK_PERIOD_MS); // sleep 2.5 seconds before starting stream 

    // uint32_t datalen = esp_wifi_get_promiscuous_data_len();
    // printf("promisc_data_len: %"PRIu32" \n", datalen);
}

void uart_init(void)
{
    // default UART should be 115200,N,8,1 (remember the 80's? 300,E,7,1)
    uart_config_t uart_config = {
        .baud_rate = CONFIG_SNIFFER_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0, CONFIG_SNIFFER_UART_BUFFER_SIZE, 0, 0, NULL, 0 );
}

void app_main(void)
{
    uint8_t led = 0;
#ifdef CONFIG_SNIFFER_CHANNEL_HOPING
    uint8_t channel = CONFIG_SNIFFER_CHANNEL;
#endif

    uart_init();
    wifi_init();
    gpio_set_direction(CONFIG_SNIFFER_LED_GPIO_PIN, GPIO_MODE_OUTPUT);

    vTaskDelay( 2500 / portTICK_PERIOD_MS); // sleep 2.5 seconds before starting stream 
    uart_write_bytes(UART_NUM_0, (const char *) "<<START>>\n", 10);
    uart_flush(UART_NUM_0);
    pcap_start();

    while (true) 
    {
        gpio_set_level(CONFIG_SNIFFER_LED_GPIO_PIN, led ^= 1);
        vTaskDelay(CONFIG_SNIFFER_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
#ifdef CONFIG_SNIFFER_CHANNEL_HOPING
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            channel = (channel % CONFIG_SNIFFER_CHANNEL_MAX) + 1;
#endif
    }
}
