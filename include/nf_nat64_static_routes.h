#ifndef _NAT64_STATIC_ROUTES_H
#define _NAT64_STATIC_ROUTES_H

#include <linux/string.h>
/** 
 * @file nf_nat64_static_routes.h
 *
 * This header contains the function prototypes for the
 * nf_nat64_static_routes.c module
 *
 */
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

/**
 * nat64_create_character_device - creates character device
 * @return the function returns 0 if the device is created correctly,
 * otherwise it returns a value less than 0.
 *
 * It registers a character device to be used by the kernel to
 * establish a two way communication method via ioctl
 *
 */
int nat64_create_character_device(void);

/**
 * nat64_destroy_character_device - destroy character device
 *
 * It destroy the character device that was used by the kernel to
 * establish a two way communication method via ioctl
 *
 */
void nat64_destroy_character_device(void);

/**
 * nat64_add_static_route - adds a static route
 * @param  b  The char buffer where the route is contained.
 * @param  buffer  The char buffer where the IPv4 addres from the pool 
 * is contained.
 *
 * It splits the char buffer and detects each parameter needed
 * to add a static route to the BIB and Session Table of NAT64.
 *
 */
void nat64_add_static_route(char *b, char *buffer);

#endif
