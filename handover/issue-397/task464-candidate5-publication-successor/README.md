# Candidate-five safe publication successor

This speculative checkpoint publishes exactly three fixed candidate-five role
names into one canonical private directory. It uses a private stage, retained
descriptors, create-only hard links, reconciliation, data and directory fsync,
and exact public-byte validation before and after the final callback while the
directory lock is held. It removes the owned staging links before authority
validation, so each public artifact has one link. Complete reads through EOF
bind the exact size and bytes. Rollback unconditionally reconciles every public
and stage name from its recorded transaction-owned inode. Rollback
removes only transaction-owned inodes. Before it closes each retained
descriptor, it requires the owned inode to have zero links. It reports a moved
or otherwise untracked owned link as residue and does not claim full rollback.

POSIX does not provide crash-atomic publication for three names. Process death
can leave a partial set. Consumers must reject an incomplete set. This helper
does not overwrite or adopt foreign paths. It does not run Git, replay, a
candidate shell, a network operation, credentials, sockets, or Hermes.

This checkpoint cannot be integrated or approved before checkpoint #401 and an
independent review of these exact bytes.
