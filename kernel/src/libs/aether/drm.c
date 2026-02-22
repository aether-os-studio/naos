#include <libs/aether/drm.h>
#include <mod/dlinker.h>

EXPORT_SYMBOL(drm_regist_pci_dev);
EXPORT_SYMBOL(drm_register_device);
EXPORT_SYMBOL(drm_device_set_driver_info);
EXPORT_SYMBOL(drm_unregister_device);
EXPORT_SYMBOL(drm_init_after_pci_sysfs);

EXPORT_SYMBOL(drm_resource_manager_init);
EXPORT_SYMBOL(drm_resource_manager_cleanup);
EXPORT_SYMBOL(drm_crtc_get);
EXPORT_SYMBOL(drm_crtc_alloc);
EXPORT_SYMBOL(drm_crtc_free);
EXPORT_SYMBOL(drm_encoder_get);
EXPORT_SYMBOL(drm_encoder_alloc);
EXPORT_SYMBOL(drm_encoder_free);
EXPORT_SYMBOL(drm_plane_get);
EXPORT_SYMBOL(drm_plane_alloc);
EXPORT_SYMBOL(drm_plane_free);
EXPORT_SYMBOL(drm_connector_get);
EXPORT_SYMBOL(drm_connector_alloc);
EXPORT_SYMBOL(drm_connector_free);
EXPORT_SYMBOL(drm_framebuffer_get);
EXPORT_SYMBOL(drm_framebuffer_alloc);
EXPORT_SYMBOL(drm_framebuffer_free);
EXPORT_SYMBOL(drm_post_event);
EXPORT_SYMBOL(fast_copy_16);
