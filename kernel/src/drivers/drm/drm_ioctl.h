/*
 * DRM ioctl declarations
 *
 * This file contains declarations for DRM ioctl handling functions.
 * It separates the ioctl implementation from the core driver framework.
 */

#ifndef _DRM_IOCTL_H
#define _DRM_IOCTL_H

#include "drm.h"

/**
 * drm_ioctl - Main DRM ioctl handler
 * @data: DRM device pointer
 * @cmd: IOCTL command
 * @arg: IOCTL argument
 *
 * Handles all DRM ioctl commands. Returns 0 on success, negative error code on
 * failure.
 */
ssize_t drm_ioctl(void *data, ssize_t cmd, ssize_t arg);

/**
 * drm_ioctl_version - Handle DRM_IOCTL_VERSION
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_version(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_get_cap - Handle DRM_IOCTL_GET_CAP
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_get_cap(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getresources - Handle DRM_IOCTL_MODE_GETRESOURCES
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getresources(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getcrtc - Handle DRM_IOCTL_MODE_GETCRTC
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getcrtc(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getencoder - Handle DRM_IOCTL_MODE_GETENCODER
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getencoder(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_create_dumb - Handle DRM_IOCTL_MODE_CREATE_DUMB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_create_dumb(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_map_dumb - Handle DRM_IOCTL_MODE_MAP_DUMB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_map_dumb(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getconnector - Handle DRM_IOCTL_MODE_GETCONNECTOR
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getconnector(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getfb - Handle DRM_IOCTL_MODE_GETFB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getfb(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_addfb - Handle DRM_IOCTL_MODE_ADDFB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_addfb(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_addfb2 - Handle DRM_IOCTL_MODE_ADDFB2
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_addfb2(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_setcrtc - Handle DRM_IOCTL_MODE_SETCRTC
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_setcrtc(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getplaneresources - Handle DRM_IOCTL_MODE_GETPLANERESOURCES
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getplaneresources(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getplane - Handle DRM_IOCTL_MODE_GETPLANE
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getplane(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_setplane - Handle DRM_IOCTL_MODE_SETPLANE
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_setplane(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getproperty - Handle DRM_IOCTL_MODE_GETPROPERTY
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getproperty(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_getpropblob - Handle DRM_IOCTL_MODE_GETPROPBLOB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_getpropblob(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_obj_getproperties - Handle DRM_IOCTL_MODE_OBJ_GETPROPERTIES
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_obj_getproperties(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_set_client_cap - Handle DRM_IOCTL_SET_CLIENT_CAP
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_set_client_cap(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_wait_vblank - Handle DRM_IOCTL_WAIT_VBLANK
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_wait_vblank(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_get_unique - Handle DRM_IOCTL_GET_UNIQUE
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_get_unique(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_page_flip - Handle DRM_IOCTL_MODE_PAGE_FLIP
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_page_flip(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_cursor - Handle DRM_IOCTL_MODE_CURSOR
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_cursor(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_get_magic - Handle DRM_IOCTL_GET_MAGIC
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_get_magic(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_auth_magic - Handle DRM_IOCTL_AUTH_MAGIC
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_auth_magic(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_set_master - Handle DRM_IOCTL_SET_MASTER
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_set_master(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_drop_master - Handle DRM_IOCTL_DROP_MASTER
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_drop_master(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_gamma - Handle DRM_IOCTL_MODE_GETGAMMA/DRM_IOCTL_MODE_SETGAMMA
 * @dev: DRM device
 * @arg: ioctl argument
 * @cmd: command (GET or SET)
 */
int drm_ioctl_gamma(drm_device_t *dev, void *arg, ssize_t cmd);

/**
 * drm_ioctl_dirtyfb - Handle DRM_IOCTL_MODE_DIRTYFB
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_dirtyfb(drm_device_t *dev, void *arg);

/**
 * drm_ioctl_mode_list_lessees - Handle DRM_IOCTL_MODE_LIST_LESSEES
 * @dev: DRM device
 * @arg: ioctl argument
 */
int drm_ioctl_mode_list_lessees(drm_device_t *dev, void *arg);

#endif /* _DRM_IOCTL_H */
