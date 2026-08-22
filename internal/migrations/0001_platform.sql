CREATE TABLE platform.configuration_versions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint text NOT NULL UNIQUE,
    openfga_model_id text NOT NULL,
    schema_version text NOT NULL,
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
    is_active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    CONSTRAINT configuration_activation_valid CHECK (
        (is_active AND activated_at IS NOT NULL) OR (NOT is_active)
    )
);
CREATE UNIQUE INDEX configuration_versions_one_active
    ON platform.configuration_versions ((is_active)) WHERE is_active;

CREATE TABLE platform.audiences (
    id text PRIMARY KEY,
    display_name text NOT NULL,
    token_ttl_seconds integer NOT NULL,
    delegation_mode text NOT NULL DEFAULT 'disabled',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audience_id_not_empty CHECK (id <> ''),
    CONSTRAINT audience_ttl_positive CHECK (token_ttl_seconds > 0),
    CONSTRAINT audience_delegation_mode CHECK (
        delegation_mode IN ('disabled', 'subject', 'intersection', 'actor', 'union')
    )
);

CREATE TABLE platform.resources (
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_type, resource_id),
    CONSTRAINT resource_type_not_empty CHECK (resource_type <> ''),
    CONSTRAINT resource_id_not_empty CHECK (resource_id <> '')
);

CREATE TABLE platform.groups (
    id text PRIMARY KEY,
    display_name text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT group_id_not_empty CHECK (id <> '')
);

CREATE TABLE platform.resource_relationships (
    source_type text NOT NULL,
    source_id text NOT NULL,
    relation text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    cardinality text NOT NULL DEFAULT 'many',
    tuple_object text NOT NULL,
    tuple_relation text NOT NULL,
    tuple_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_type, source_id, relation, target_type, target_id),
    FOREIGN KEY (source_type, source_id) REFERENCES platform.resources(resource_type, resource_id) ON DELETE CASCADE,
    FOREIGN KEY (target_type, target_id) REFERENCES platform.resources(resource_type, resource_id) ON DELETE CASCADE,
    CONSTRAINT relationship_name_not_empty CHECK (relation <> ''),
    CONSTRAINT relationship_cardinality CHECK (cardinality IN ('one', 'many')),
    CONSTRAINT relationship_not_self CHECK (
        source_type <> target_type OR source_id <> target_id
    )
);
CREATE UNIQUE INDEX resource_relationships_single_target
    ON platform.resource_relationships (source_type, source_id, relation)
    WHERE cardinality = 'one';
CREATE INDEX resource_relationships_target
    ON platform.resource_relationships (target_type, target_id);

CREATE TABLE platform.group_memberships (
	 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id text NOT NULL REFERENCES platform.groups(id) ON DELETE CASCADE,
    member_kind text NOT NULL,
    principal_source text,
    principal_subject text,
    member_group_id text REFERENCES platform.groups(id) ON DELETE CASCADE,
    tuple_object text NOT NULL,
    tuple_relation text NOT NULL,
    tuple_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT membership_kind CHECK (member_kind IN ('principal', 'group')),
    CONSTRAINT membership_subject_shape CHECK (
        (member_kind = 'principal' AND principal_source <> '' AND principal_subject <> '' AND member_group_id IS NULL) OR
        (member_kind = 'group' AND principal_source IS NULL AND principal_subject IS NULL AND member_group_id <> '')
    ),
    CONSTRAINT membership_not_self CHECK (member_kind <> 'group' OR group_id <> member_group_id)
);
CREATE UNIQUE INDEX group_memberships_principal_unique
    ON platform.group_memberships(group_id, principal_source, principal_subject)
    WHERE member_kind = 'principal';
CREATE UNIQUE INDEX group_memberships_group_unique
    ON platform.group_memberships(group_id, member_group_id)
    WHERE member_kind = 'group';
CREATE INDEX group_memberships_nested_group ON platform.group_memberships(member_group_id)
    WHERE member_kind = 'group';

CREATE TABLE platform.grants (
    id text PRIMARY KEY,
    subject_kind text NOT NULL,
    principal_source text,
    principal_subject text,
    subject_group_id text REFERENCES platform.groups(id) ON DELETE CASCADE,
    role text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    tuple_object text NOT NULL,
    tuple_relation text NOT NULL,
    tuple_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (resource_type, resource_id) REFERENCES platform.resources(resource_type, resource_id) ON DELETE CASCADE,
    CONSTRAINT grant_id_not_empty CHECK (id <> ''),
    CONSTRAINT grant_subject_kind CHECK (subject_kind IN ('principal', 'group')),
    CONSTRAINT grant_subject_shape CHECK (
        (subject_kind = 'principal' AND principal_source <> '' AND principal_subject <> '' AND subject_group_id IS NULL) OR
        (subject_kind = 'group' AND principal_source IS NULL AND principal_subject IS NULL AND subject_group_id <> '')
    ),
    CONSTRAINT grant_role_not_empty CHECK (role <> '')
);
CREATE UNIQUE INDEX grants_principal_unique
    ON platform.grants(principal_source, principal_subject, role, resource_type, resource_id)
    WHERE subject_kind = 'principal';
CREATE UNIQUE INDEX grants_group_unique
    ON platform.grants(subject_group_id, role, resource_type, resource_id)
    WHERE subject_kind = 'group';
CREATE INDEX grants_resource ON platform.grants(resource_type, resource_id);
CREATE INDEX grants_group_subject ON platform.grants(subject_group_id) WHERE subject_kind = 'group';

-- Application-level tuple intent/outbox. Workers apply these operations through
-- OpenFGA's supported interfaces; this table is not an OpenFGA tuple store.
CREATE TABLE platform.authorization_operations (
    operation_id text PRIMARY KEY,
    action text NOT NULL,
    object text NOT NULL,
    relation text NOT NULL,
    subject text NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT authorization_operation_action CHECK (action IN ('write', 'delete')),
    CONSTRAINT authorization_operation_state CHECK (state IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT authorization_operation_values CHECK (object <> '' AND relation <> '' AND subject <> '')
);
CREATE INDEX authorization_operations_work
    ON platform.authorization_operations(state, created_at)
    WHERE state IN ('pending', 'failed');

CREATE TABLE platform.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    request_id text,
    actor_principal text,
    operation text NOT NULL,
    target text NOT NULL,
    result text NOT NULL,
    previous_value jsonb,
    new_value jsonb,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT audit_operation_not_empty CHECK (operation <> ''),
    CONSTRAINT audit_target_not_empty CHECK (target <> ''),
    CONSTRAINT audit_result_not_empty CHECK (result <> '')
);
CREATE INDEX audit_events_occurred_at ON platform.audit_events(occurred_at DESC);
CREATE INDEX audit_events_request_id ON platform.audit_events(request_id) WHERE request_id IS NOT NULL;
