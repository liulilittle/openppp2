/*
 Navicat MySQL Data Transfer

 Source Server         : 172.31.109.138
 Source Server Type    : MySQL
 Source Server Version : 50742
 Source Host           : 172.31.109.138:3306
 Source Schema         : ppp

 Target Server Type    : MySQL
 Target Server Version : 50742
 File Encoding         : 65001

 Date: 18/01/2024 17:52:33
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for tb_servers
-- ----------------------------
DROP TABLE IF EXISTS `tb_servers`;
CREATE TABLE `tb_servers`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `link` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `name` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `kf` bigint(20) NOT NULL,
  `kx` bigint(20) NOT NULL,
  `kl` bigint(20) NOT NULL,
  `kh` bigint(20) NOT NULL,
  `protocol` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `protocol_key` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `transport` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `transport_key` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `masked` tinyint(1) NOT NULL,
  `plaintext` tinyint(1) NOT NULL,
  `delta_encode` tinyint(1) NOT NULL,
  `shuffle_data` tinyint(1) NOT NULL,
  `qos` int(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for tb_users
-- ----------------------------
DROP TABLE IF EXISTS `tb_users`;
CREATE TABLE `tb_users`  (
  `guid` varchar(36) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `incoming_traffic` bigint(20) UNSIGNED NOT NULL,
  `outgoing_traffic` bigint(20) UNSIGNED NOT NULL,
  `expired_time` int(10) UNSIGNED NOT NULL,
  `qos` int(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`guid`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for tb_subscriptions
-- ----------------------------
DROP TABLE IF EXISTS `tb_subscriptions`;
CREATE TABLE `tb_subscriptions`  (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_guid` varchar(36) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `profile_prefix` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
  `server_ids` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `options_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime(3) NULL,
  `updated_at` datetime(3) NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `idx_tb_subscriptions_token` (`token`) USING BTREE,
  KEY `idx_tb_subscriptions_user_guid` (`user_guid`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
