-- Placed in the public domain 20040924
--
-- Example SQLite database schema for flowinsert.pl script.
-- 
-- Create SQLite database using:
--   sqlite -init flows.sql flows.sqlite
--
-- $Id: flows.sql,v 1.1 2004/09/24 05:49:32 djm Exp $

CREATE TABLE flows (
	tag		INTEGER,
        received	TIMESTAMP,
	agent_addr	VARCHAR(64),
	src_addr	VARCHAR(64),
	dst_addr	VARCHAR(64),
        src_port	INTEGER,
        dst_port	INTEGER,
        octets		INTEGER,
        packets		INTEGER,
        protocol	INTEGER
);

