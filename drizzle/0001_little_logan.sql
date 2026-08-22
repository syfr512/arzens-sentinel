CREATE TABLE `findings` (
	`id` varchar(80) NOT NULL,
	`scanId` varchar(32) NOT NULL,
	`ruleId` varchar(32) NOT NULL,
	`title` varchar(512) NOT NULL,
	`category` varchar(128) NOT NULL,
	`severity` enum('critical','high','medium','low','informational') NOT NULL,
	`originalSeverity` enum('critical','high','medium','low','informational') NOT NULL,
	`scoreTenth` int NOT NULL,
	`confidence` enum('high','medium','low') NOT NULL,
	`endpoint` varchar(2048) NOT NULL,
	`evidence` text NOT NULL,
	`rationale` json NOT NULL,
	`reference` varchar(1024) NOT NULL,
	`remediation` text NOT NULL,
	`status` enum('open','in_review','accepted_risk','remediated') NOT NULL DEFAULT 'open',
	`reviewerNote` text,
	`severityOverrideNote` text,
	`source` enum('native','zap','demo') NOT NULL DEFAULT 'native',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `remediation_recommendations` (
	`id` varchar(32) NOT NULL,
	`scanId` varchar(32) NOT NULL,
	`findingId` varchar(80) NOT NULL,
	`source` enum('deterministic','ai') NOT NULL,
	`guidance` json NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `remediation_recommendations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `report_artifacts` (
	`id` varchar(32) NOT NULL,
	`scanId` varchar(32) NOT NULL,
	`format` enum('json','html','pdf') NOT NULL,
	`storageKey` varchar(512) NOT NULL,
	`url` varchar(1024) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `report_artifacts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_endpoints` (
	`id` varchar(40) NOT NULL,
	`scanId` varchar(32) NOT NULL,
	`url` varchar(2048) NOT NULL,
	`statusCode` int NOT NULL,
	`contentType` varchar(255),
	`discoveredBy` varchar(32) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_endpoints_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_events` (
	`id` varchar(32) NOT NULL,
	`scanId` varchar(32) NOT NULL,
	`label` varchar(128) NOT NULL,
	`detail` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_runs` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`targetId` varchar(32) NOT NULL,
	`targetUrl` varchar(2048) NOT NULL,
	`profile` enum('safe_passive','active_lab') NOT NULL DEFAULT 'safe_passive',
	`status` enum('queued','running','completed','failed') NOT NULL DEFAULT 'queued',
	`riskScore` int NOT NULL DEFAULT 0,
	`overallSeverity` enum('critical','high','medium','low','informational') NOT NULL DEFAULT 'informational',
	`endpointCount` int NOT NULL DEFAULT 0,
	`findingCount` int NOT NULL DEFAULT 0,
	`errorMessage` text,
	`startedAt` timestamp,
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_runs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_targets` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`normalizedUrl` varchar(2048) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `scan_targets_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `findings_scan_idx` ON `findings` (`scanId`);--> statement-breakpoint
CREATE INDEX `findings_rule_endpoint_idx` ON `findings` (`scanId`,`ruleId`);--> statement-breakpoint
CREATE INDEX `remediation_finding_idx` ON `remediation_recommendations` (`findingId`);--> statement-breakpoint
CREATE INDEX `report_artifacts_scan_idx` ON `report_artifacts` (`scanId`);--> statement-breakpoint
CREATE INDEX `scan_endpoints_scan_idx` ON `scan_endpoints` (`scanId`);--> statement-breakpoint
CREATE INDEX `scan_events_scan_idx` ON `scan_events` (`scanId`);--> statement-breakpoint
CREATE INDEX `scan_runs_user_created_idx` ON `scan_runs` (`userId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `scan_targets_user_url_idx` ON `scan_targets` (`userId`,`normalizedUrl`);