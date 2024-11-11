/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __TRACE_BPF_SKEL_H__
#define __TRACE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct trace_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *bpf_prog1;
	} progs;
	struct {
		struct bpf_link *bpf_prog1;
	} links;

#ifdef __cplusplus
	static inline struct trace_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct trace_bpf *open_and_load();
	static inline int load(struct trace_bpf *skel);
	static inline int attach(struct trace_bpf *skel);
	static inline void detach(struct trace_bpf *skel);
	static inline void destroy(struct trace_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
trace_bpf__destroy(struct trace_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
trace_bpf__create_skeleton(struct trace_bpf *obj);

static inline struct trace_bpf *
trace_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct trace_bpf *obj;
	int err;

	obj = (struct trace_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = trace_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	trace_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct trace_bpf *
trace_bpf__open(void)
{
	return trace_bpf__open_opts(NULL);
}

static inline int
trace_bpf__load(struct trace_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct trace_bpf *
trace_bpf__open_and_load(void)
{
	struct trace_bpf *obj;
	int err;

	obj = trace_bpf__open();
	if (!obj)
		return NULL;
	err = trace_bpf__load(obj);
	if (err) {
		trace_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
trace_bpf__attach(struct trace_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
trace_bpf__detach(struct trace_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *trace_bpf__elf_bytes(size_t *sz);

static inline int
trace_bpf__create_skeleton(struct trace_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "trace_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "trace_bp.rodata";
	s->maps[0].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "bpf_prog1";
	s->progs[0].prog = &obj->progs.bpf_prog1;
	s->progs[0].link = &obj->links.bpf_prog1;

	s->data = trace_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *trace_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xa0\x10\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1b\0\
\x01\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x0f\0\0\0\x85\0\0\0\x06\
\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x48\x61\x70\x70\x79\x20\x72\x61\x20\
\x61\x79\x79\x61\x0a\0\x47\x50\x4c\0\0\x0c\x08\x06\0\x01\x11\x01\x25\x25\x13\
\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\0\0\x02\x2e\x01\
\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\
\x19\0\0\x03\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x04\x05\0\x03\
\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x05\x01\x01\x49\x13\0\0\x06\x21\0\x49\x13\x37\
\x0b\0\0\x07\x26\0\x49\x13\0\0\x08\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x09\x24\0\
\x03\x25\x0b\x0b\x3e\x0b\0\0\x0a\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x0b\
\x0f\0\x49\x13\0\0\x0c\x15\x01\x49\x13\x27\x19\0\0\x0d\x05\0\x49\x13\0\0\x0e\
\x18\0\0\0\x0f\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\x10\x34\0\x03\x25\x49\
\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x11\x13\x01\x03\x25\x0b\x0b\x3a\x0b\
\x3b\x05\0\0\x12\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\x38\x0b\0\0\0\xa4\x01\0\
\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\0\0\0\0\0\x02\x03\x30\0\0\0\
\x08\0\0\0\x02\x03\x30\0\0\0\x01\x5a\x0d\0\x0c\xc1\0\0\0\x03\x03\x46\0\0\0\0\
\x0e\x02\xa1\0\x04\x0f\0\x0c\xc5\0\0\0\0\x05\x52\0\0\0\x06\x5b\0\0\0\x0f\0\x07\
\x57\0\0\0\x08\x04\x06\x01\x09\x05\x08\x07\x0a\x06\x67\0\0\0\x02\xb1\x07\x6c\0\
\0\0\x0b\x71\0\0\0\x0c\x82\0\0\0\x0d\x86\0\0\0\x0d\x8b\0\0\0\x0e\0\x08\x07\x05\
\x08\x0b\x52\0\0\0\x0f\x93\0\0\0\x09\x01\x0c\x08\x08\x07\x04\x10\x0a\xa2\0\0\0\
\0\x13\x02\xa1\x01\x05\x57\0\0\0\x06\x5b\0\0\0\x04\0\x10\x0b\xb9\0\0\0\0\x14\
\x02\xa1\x02\x0f\x8b\0\0\0\x0c\x01\x16\x08\x0e\x05\x04\x0b\xca\0\0\0\x11\x26\
\xa8\x01\x4f\x04\x12\x10\xa3\x01\0\0\x01\x50\x04\0\x12\x12\xa3\x01\0\0\x01\x51\
\x04\x08\x12\x13\xa3\x01\0\0\x01\x52\x04\x10\x12\x14\xa3\x01\0\0\x01\x53\x04\
\x18\x12\x15\xa3\x01\0\0\x01\x54\x04\x20\x12\x16\xa3\x01\0\0\x01\x55\x04\x28\
\x12\x17\xa3\x01\0\0\x01\x56\x04\x30\x12\x18\xa3\x01\0\0\x01\x57\x04\x38\x12\
\x19\xa3\x01\0\0\x01\x58\x04\x40\x12\x1a\xa3\x01\0\0\x01\x59\x04\x48\x12\x1b\
\xa3\x01\0\0\x01\x5a\x04\x50\x12\x1c\xa3\x01\0\0\x01\x5b\x04\x58\x12\x1d\xa3\
\x01\0\0\x01\x5c\x04\x60\x12\x1e\xa3\x01\0\0\x01\x5d\x04\x68\x12\x1f\xa3\x01\0\
\0\x01\x5e\x04\x70\x12\x20\xa3\x01\0\0\x01\x5f\x04\x78\x12\x21\xa3\x01\0\0\x01\
\x60\x04\x80\x12\x22\xa3\x01\0\0\x01\x61\x04\x88\x12\x23\xa3\x01\0\0\x01\x62\
\x04\x90\x12\x24\xa3\x01\0\0\x01\x63\x04\x98\x12\x25\xa3\x01\0\0\x01\x64\x04\
\xa0\0\x08\x11\x07\x08\0\xa0\0\0\0\x05\0\0\0\0\0\0\0\x27\0\0\0\x33\0\0\0\x53\0\
\0\0\x55\0\0\0\x5a\0\0\0\x6e\0\0\0\x7f\0\0\0\x84\0\0\0\x91\0\0\0\x97\0\0\0\xa0\
\0\0\0\xa9\0\0\0\xad\0\0\0\xb7\0\0\0\xbb\0\0\0\xbf\0\0\0\xc3\0\0\0\xd1\0\0\0\
\xd5\0\0\0\xd9\0\0\0\xdd\0\0\0\xe0\0\0\0\xe3\0\0\0\xe7\0\0\0\xeb\0\0\0\xee\0\0\
\0\xf1\0\0\0\xf4\0\0\0\xf7\0\0\0\xfa\0\0\0\xfd\0\0\0\0\x01\0\0\x08\x01\0\0\x0b\
\x01\0\0\x0e\x01\0\0\x14\x01\0\0\x17\x01\0\0\x1a\x01\0\0\x55\x62\x75\x6e\x74\
\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x38\x2e\
\x31\x2e\x33\x20\x28\x31\x75\x62\x75\x6e\x74\x75\x31\x29\0\x74\x72\x61\x63\x65\
\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x73\x75\x79\x72\x61\x2f\x44\
\x65\x73\x6b\x74\x6f\x70\x2f\x4b\x70\x72\x6f\x62\x65\x2d\x74\x65\x73\x74\0\x73\
\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\
\x59\x50\x45\x5f\x5f\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\
\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\
\x5f\x5f\x75\x33\x32\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x5f\x76\x65\x72\x73\
\x69\x6f\x6e\0\x75\x33\x32\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\0\x69\x6e\x74\
\0\x63\x74\x78\0\x72\x31\x35\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\
\x67\0\x72\x31\x34\0\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\x62\x78\0\x72\x31\
\x31\0\x72\x31\x30\0\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\x64\x78\0\x73\x69\
\0\x64\x69\0\x6f\x72\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\0\x66\x6c\x61\x67\
\x73\0\x73\x70\0\x73\x73\0\x70\x74\x5f\x72\x65\x67\x73\0\x24\0\0\0\x05\0\x08\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\
\0\x18\0\0\0\0\0\0\0\x50\x02\0\0\x50\x02\0\0\x4e\x01\0\0\0\0\0\0\0\0\0\x02\x02\
\0\0\0\x01\0\0\0\x15\0\0\x04\xa8\0\0\0\x09\0\0\0\x03\0\0\0\0\0\0\0\x0d\0\0\0\
\x03\0\0\0\x40\0\0\0\x11\0\0\0\x03\0\0\0\x80\0\0\0\x15\0\0\0\x03\0\0\0\xc0\0\0\
\0\x19\0\0\0\x03\0\0\0\0\x01\0\0\x1c\0\0\0\x03\0\0\0\x40\x01\0\0\x1f\0\0\0\x03\
\0\0\0\x80\x01\0\0\x23\0\0\0\x03\0\0\0\xc0\x01\0\0\x27\0\0\0\x03\0\0\0\0\x02\0\
\0\x2a\0\0\0\x03\0\0\0\x40\x02\0\0\x2d\0\0\0\x03\0\0\0\x80\x02\0\0\x30\0\0\0\
\x03\0\0\0\xc0\x02\0\0\x33\0\0\0\x03\0\0\0\0\x03\0\0\x36\0\0\0\x03\0\0\0\x40\
\x03\0\0\x39\0\0\0\x03\0\0\0\x80\x03\0\0\x3c\0\0\0\x03\0\0\0\xc0\x03\0\0\x44\0\
\0\0\x03\0\0\0\0\x04\0\0\x47\0\0\0\x03\0\0\0\x40\x04\0\0\x4a\0\0\0\x03\0\0\0\
\x80\x04\0\0\x50\0\0\0\x03\0\0\0\xc0\x04\0\0\x53\0\0\0\x03\0\0\0\0\x05\0\0\x56\
\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\x05\0\0\0\x64\0\0\0\
\x01\0\0\0\x68\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x6c\0\0\0\x01\0\0\x0c\x04\
\0\0\0\0\0\0\0\0\0\0\x0a\x08\0\0\0\xe8\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\
\0\0\0\0\0\0\x03\0\0\0\0\x07\0\0\0\x0a\0\0\0\x0f\0\0\0\xed\0\0\0\0\0\0\x01\x04\
\0\0\0\x20\0\0\0\x01\x01\0\0\0\0\0\x0e\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\
\0\0\x08\0\0\0\x0a\0\0\0\x04\0\0\0\x0d\x01\0\0\0\0\0\x0e\x0c\0\0\0\x01\0\0\0\
\x16\x01\0\0\0\0\0\x08\x0f\0\0\0\x1a\x01\0\0\0\0\0\x08\x10\0\0\0\x20\x01\0\0\0\
\0\0\x01\x04\0\0\0\x20\0\0\0\x2d\x01\0\0\0\0\0\x0e\x0e\0\0\0\x01\0\0\0\x36\x01\
\0\0\x01\0\0\x0f\0\0\0\0\x0b\0\0\0\0\0\0\0\x0f\0\0\0\x3e\x01\0\0\x01\0\0\x0f\0\
\0\0\0\x0d\0\0\0\0\0\0\0\x04\0\0\0\x46\x01\0\0\x01\0\0\x0f\0\0\0\0\x11\0\0\0\0\
\0\0\0\x04\0\0\0\0\x70\x74\x5f\x72\x65\x67\x73\0\x72\x31\x35\0\x72\x31\x34\0\
\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\x62\x78\0\x72\x31\x31\0\x72\x31\x30\0\
\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\x64\x78\0\x73\x69\0\x64\x69\0\x6f\x72\
\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\0\x66\x6c\x61\x67\x73\0\x73\x70\0\x73\
\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x69\
\x6e\x74\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\0\x6b\x70\x72\x6f\x62\x65\x2f\
\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\x74\x5f\x6e\x73\0\x2f\x68\x6f\
\x6d\x65\x2f\x73\x75\x79\x72\x61\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x4b\x70\
\x72\x6f\x62\x65\x2d\x74\x65\x73\x74\x2f\x74\x72\x61\x63\x65\x2e\x62\x70\x66\
\x2e\x63\0\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\
\x6b\x28\x73\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x73\x29\x29\x3b\0\x20\x20\x72\
\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\
\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x62\x70\x66\x5f\x70\x72\
\x6f\x67\x31\x2e\x73\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x75\x33\x32\0\x5f\x5f\
\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x76\x65\
\x72\x73\x69\x6f\x6e\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\
\x65\0\x76\x65\x72\x73\x69\x6f\x6e\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\
\0\0\x14\0\0\0\x2c\0\0\0\x40\0\0\0\0\0\0\0\x08\0\0\0\x76\0\0\0\x01\0\0\0\0\0\0\
\0\x06\0\0\0\x10\0\0\0\x76\0\0\0\x02\0\0\0\0\0\0\0\x8e\0\0\0\xba\0\0\0\x03\x3c\
\0\0\x20\0\0\0\x8e\0\0\0\xdc\0\0\0\x03\x40\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\
\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\
\0\0\x8a\0\0\0\x05\0\x08\0\x69\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\
\0\0\0\x01\0\0\x01\x01\x01\x1f\x03\0\0\0\0\x20\0\0\0\x22\0\0\0\x03\x01\x1f\x02\
\x0f\x05\x1e\x03\x39\0\0\0\0\x07\x33\x79\xdb\x3d\xbe\xe6\xad\x15\x7e\x2b\x3a\
\x6e\x98\x28\xc4\x45\0\0\0\x01\x9d\xe9\x5d\xcd\x80\x68\xd5\xd2\x57\xf0\xfa\x11\
\x15\x08\xfe\xbf\x4f\0\0\0\x02\xc4\x54\x1a\xc9\xeb\x57\x75\xba\x77\x80\x51\xc9\
\x40\xb0\x3a\x18\x04\0\x05\x03\x0a\0\x09\x02\0\0\0\0\0\0\0\0\x03\x0e\x01\x4b\
\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x73\x75\x79\x72\x61\x2f\x44\x65\x73\
\x6b\x74\x6f\x70\x2f\x4b\x70\x72\x6f\x62\x65\x2d\x74\x65\x73\x74\0\x2e\0\x2f\
\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\
\x70\x66\0\x74\x72\x61\x63\x65\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\x6c\x69\x6e\
\x75\x78\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\
\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdd\0\0\0\x04\0\
\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x55\0\0\0\x01\0\x05\0\0\0\0\0\0\0\0\0\x0f\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x18\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x0a\x01\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\
\xb3\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x9c\0\0\0\x11\0\x07\0\
\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x08\0\0\
\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x15\0\0\0\
\0\0\0\0\x03\0\0\0\x0a\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x08\0\0\0\0\
\0\0\0\x03\0\0\0\x07\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x10\0\0\0\0\0\
\0\0\x03\0\0\0\x07\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x18\0\0\0\0\0\0\
\0\x03\0\0\0\x07\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x20\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x28\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x30\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x38\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x40\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x48\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x50\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x58\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x60\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x68\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x70\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x74\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x78\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x7c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x80\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x84\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x88\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x8c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x90\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x94\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x98\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x9c\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\xa0\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x04\0\0\0\x10\0\0\0\0\0\0\0\
\x02\0\0\0\x0d\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x0e\0\0\0\x20\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x30\x02\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x48\x02\0\0\0\0\0\
\0\x04\0\0\0\x0d\0\0\0\x60\x02\0\0\0\0\0\0\x04\0\0\0\x0e\0\0\0\x2c\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x26\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x36\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x4b\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x60\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x7d\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x0c\x03\x0d\x0e\0\
\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x64\x65\
\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x72\x65\x6c\
\x6b\x70\x72\x6f\x62\x65\x2f\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\
\x74\x5f\x6e\x73\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\x2e\x73\0\x2e\x64\x65\
\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\
\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x5f\x76\x65\x72\
\x73\x69\x6f\x6e\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\
\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\
\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\
\0\x74\x72\x61\x63\x65\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\
\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\
\x2e\x42\x54\x46\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe9\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x8c\x0f\0\0\0\0\0\0\x14\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3d\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x30\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x39\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x0b\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1a\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xf9\0\0\0\x01\0\0\0\x02\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb4\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x7f\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x9d\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\0\
\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\0\0\0\0\0\0\0\xdd\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x65\x01\0\0\0\0\0\0\xa8\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\0\0\0\x09\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x0b\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1a\0\0\0\x09\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x26\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x0d\x03\0\0\0\0\0\0\xa4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe8\x0b\0\0\0\0\0\0\x70\x02\0\0\0\0\0\0\x1a\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x61\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb1\
\x03\0\0\0\0\0\0\x22\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd3\x04\0\0\0\0\
\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7c\0\
\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x0e\0\0\0\0\0\0\x40\0\0\0\
\0\0\0\0\x1a\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x05\x01\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfc\x04\0\0\0\0\0\0\xb6\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x01\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x0e\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x1a\0\
\0\0\x10\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xb4\x08\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xc8\x0e\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x1a\0\0\0\x12\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\xd0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x18\x09\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xcc\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\x0e\0\0\0\
\0\0\0\x20\0\0\0\0\0\0\0\x1a\0\0\0\x14\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\xc0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x09\0\0\0\0\0\0\x8e\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbc\0\0\0\x09\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x0f\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\
\x1a\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x6c\0\0\0\x01\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xce\x09\0\0\0\0\0\0\x61\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xa5\0\0\0\x03\x4c\xff\x6f\0\0\0\
\x80\0\0\0\0\0\0\0\0\0\0\0\0\x88\x0f\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x1a\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf1\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x30\x0a\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\0\x08\
\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct trace_bpf *trace_bpf::open(const struct bpf_object_open_opts *opts) { return trace_bpf__open_opts(opts); }
struct trace_bpf *trace_bpf::open_and_load() { return trace_bpf__open_and_load(); }
int trace_bpf::load(struct trace_bpf *skel) { return trace_bpf__load(skel); }
int trace_bpf::attach(struct trace_bpf *skel) { return trace_bpf__attach(skel); }
void trace_bpf::detach(struct trace_bpf *skel) { trace_bpf__detach(skel); }
void trace_bpf::destroy(struct trace_bpf *skel) { trace_bpf__destroy(skel); }
const void *trace_bpf::elf_bytes(size_t *sz) { return trace_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
trace_bpf__assert(struct trace_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __TRACE_BPF_SKEL_H__ */