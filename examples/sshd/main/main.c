#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "example.h"

static void
initialize_nvs()
{
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK( nvs_flash_erase() );
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);
}

void
app_main(void)
{
	initialize_nvs();
	initialize_wifi();
	/* replace with SSID and passphrase */
	wifi_sta_join("mywifi", "supasecret");
	start_sshd();
}

