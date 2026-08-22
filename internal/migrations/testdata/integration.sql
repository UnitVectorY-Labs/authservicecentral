\set ON_ERROR_STOP on

INSERT INTO platform.resources(resource_type,resource_id) VALUES
  ('folder','finance'),('folder','legal'),('document','123'),('group','engineering'),('group','backend');
INSERT INTO platform.groups(id,display_name) VALUES ('engineering','Engineering'),('backend','Backend');

INSERT INTO platform.resource_relationships
  (source_type,source_id,relation,target_type,target_id,cardinality,tuple_object,tuple_relation,tuple_subject)
VALUES ('document','123','parent','folder','finance','one','document:123','parent','folder:finance');

-- The partial unique index rejects a second target for a single-valued relationship.
DO $$ BEGIN
  BEGIN
    INSERT INTO platform.resource_relationships
      (source_type,source_id,relation,target_type,target_id,cardinality,tuple_object,tuple_relation,tuple_subject)
    VALUES ('document','123','parent','folder','legal','one','document:123','parent','folder:legal');
    RAISE EXCEPTION 'expected cardinality violation';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
END $$;

INSERT INTO platform.group_memberships
  (group_id,member_kind,principal_source,principal_subject,tuple_object,tuple_relation,tuple_subject)
VALUES ('backend','principal','github','alice','group:backend','member','principal:github:alice');
INSERT INTO platform.group_memberships
  (group_id,member_kind,member_group_id,tuple_object,tuple_relation,tuple_subject)
VALUES ('engineering','group','backend','group:engineering','member','group:backend#member');
INSERT INTO platform.grants
  (id,subject_kind,subject_group_id,role,resource_type,resource_id,tuple_object,tuple_relation,tuple_subject)
VALUES ('grant-1','group','engineering','editor','document','123','document:123','role_editor','group:engineering#member');

DELETE FROM platform.resources WHERE resource_type='folder' AND resource_id='finance';
DO $$ BEGIN
  IF EXISTS (SELECT FROM platform.resource_relationships WHERE target_type='folder' AND target_id='finance') THEN
    RAISE EXCEPTION 'target relationship was not cascaded';
  END IF;
END $$;

DELETE FROM platform.groups WHERE id='backend';
DO $$ BEGIN
  IF EXISTS (SELECT FROM platform.group_memberships WHERE member_group_id='backend' OR group_id='backend') THEN
    RAISE EXCEPTION 'nested memberships were not cascaded';
  END IF;
END $$;

INSERT INTO platform.configuration_versions(fingerprint,openfga_model_id,schema_version,is_active,activated_at)
VALUES ('sha256:one','model-1','1',true,now());
INSERT INTO platform.audit_events(operation,target,result) VALUES ('integration.test','database','success');
INSERT INTO platform.authorization_operations(operation_id,action,object,relation,subject)
VALUES ('op-1','delete','document:123','role_editor','group:engineering#member');
