CREATE TABLE `audit_events` (
	`id` varchar(32) NOT NULL,
	`userId` int,
	`action` varchar(128) NOT NULL,
	`entityType` varchar(64) NOT NULL,
	`entityId` varchar(96),
	`outcome` enum('success','denied','failure') NOT NULL,
	`requestId` varchar(48),
	`metadata` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `audit_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `target_authorizations` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`origin` varchar(512) NOT NULL,
	`hostname` varchar(255) NOT NULL,
	`scopePath` varchar(1024) NOT NULL DEFAULT '/',
	`status` enum('pending','verified','revoked','expired') NOT NULL DEFAULT 'pending',
	`verificationMethod` enum('well_known_file') NOT NULL DEFAULT 'well_known_file',
	`verificationToken` varchar(96) NOT NULL,
	`verificationAttempts` int NOT NULL DEFAULT 0,
	`lastVerificationError` text,
	`verifiedAt` timestamp,
	`lastVerifiedAt` timestamp,
	`expiresAt` timestamp NOT NULL,
	`maxPages` int NOT NULL DEFAULT 4,
	`maxRedirects` int NOT NULL DEFAULT 3,
	`maxResponseBytes` int NOT NULL DEFAULT 350000,
	`timeoutMs` int NOT NULL DEFAULT 8000,
	`policyVersion` int NOT NULL DEFAULT 1,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `target_authorizations_id` PRIMARY KEY(`id`),
	CONSTRAINT `target_authorizations_verificationToken_unique` UNIQUE(`verificationToken`)
);
--> statement-breakpoint
ALTER TABLE `scan_runs` MODIFY COLUMN `status` enum('queued','running','completed','failed','cancelled') NOT NULL DEFAULT 'queued';--> statement-breakpoint
ALTER TABLE `report_artifacts` ADD `expiresAt` timestamp;--> statement-breakpoint
ALTER TABLE `report_artifacts` ADD `downloadCount` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `scan_runs` ADD `authorizationId` varchar(32);--> statement-breakpoint
ALTER TABLE `scan_runs` ADD `requestId` varchar(48);--> statement-breakpoint
ALTER TABLE `scan_runs` ADD `policySnapshot` json;--> statement-breakpoint
ALTER TABLE `scan_runs` ADD `cancelRequestedAt` timestamp;--> statement-breakpoint
ALTER TABLE `scan_runs` ADD `retentionExpiresAt` timestamp;--> statement-breakpoint
CREATE INDEX `audit_events_user_created_idx` ON `audit_events` (`userId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `audit_events_entity_idx` ON `audit_events` (`entityType`,`entityId`);--> statement-breakpoint
CREATE INDEX `target_authorizations_user_origin_idx` ON `target_authorizations` (`userId`,`origin`);--> statement-breakpoint
CREATE INDEX `target_authorizations_user_status_idx` ON `target_authorizations` (`userId`,`status`);--> statement-breakpoint
CREATE INDEX `scan_runs_authorization_status_idx` ON `scan_runs` (`authorizationId`,`status`);