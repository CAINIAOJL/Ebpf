/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __BIOPATTERN_SKEL_H__
#define __BIOPATTERN_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct biopattern {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *counters;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *handle__block_rq_complete;
	} progs;
	struct {
		struct bpf_link *handle__block_rq_complete;
	} links;
	struct biopattern__rodata {
		bool filter_dev;
		__u32 targ_dev;
	} *rodata;

#ifdef __cplusplus
	static inline struct biopattern *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct biopattern *open_and_load();
	static inline int load(struct biopattern *skel);
	static inline int attach(struct biopattern *skel);
	static inline void detach(struct biopattern *skel);
	static inline void destroy(struct biopattern *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
biopattern__destroy(struct biopattern *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
biopattern__create_skeleton(struct biopattern *obj);

static inline struct biopattern *
biopattern__open_opts(const struct bpf_object_open_opts *opts)
{
	struct biopattern *obj;
	int err;

	obj = (struct biopattern *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = biopattern__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	biopattern__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct biopattern *
biopattern__open(void)
{
	return biopattern__open_opts(NULL);
}

static inline int
biopattern__load(struct biopattern *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct biopattern *
biopattern__open_and_load(void)
{
	struct biopattern *obj;
	int err;

	obj = biopattern__open();
	if (!obj)
		return NULL;
	err = biopattern__load(obj);
	if (err) {
		biopattern__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
biopattern__attach(struct biopattern *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
biopattern__detach(struct biopattern *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *biopattern__elf_bytes(size_t *sz);

static inline int
biopattern__create_skeleton(struct biopattern *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "biopattern";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "counters";
	s->maps[0].map = &obj->maps.counters;

	s->maps[1].name = "biopatte.rodata";
	s->maps[1].map = &obj->maps.rodata;
	s->maps[1].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "handle__block_rq_complete";
	s->progs[0].prog = &obj->progs.handle__block_rq_complete;
	s->progs[0].link = &obj->links.handle__block_rq_complete;

	s->data = biopattern__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *biopattern__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xd8\x26\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1c\0\
\x01\0\xbf\x16\0\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\x7b\x1a\
\xf0\xff\0\0\0\0\x7b\x1a\xe8\xff\0\0\0\0\x7b\x1a\xe0\xff\0\0\0\0\xb7\x01\0\0\
\x01\0\0\0\x15\x01\x11\0\0\0\0\0\xb7\x01\0\0\x08\0\0\0\xbf\x63\0\0\0\0\0\0\x0f\
\x13\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xb7\x02\0\0\
\x08\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x01\0\0\x10\0\0\0\xbf\x63\0\0\0\0\0\0\x0f\
\x13\0\0\0\0\0\0\x79\xa7\xd8\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\
\xff\xff\xff\xb7\x02\0\0\x04\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x01\0\0\0\0\0\0\x05\
\0\x10\0\0\0\0\0\xb7\x01\0\0\x08\0\0\0\xbf\x63\0\0\0\0\0\0\x0f\x13\0\0\0\0\0\0\
\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xb7\x02\0\0\x08\0\0\0\x85\0\0\
\0\x71\0\0\0\xb7\x01\0\0\x10\0\0\0\xbf\x63\0\0\0\0\0\0\x0f\x13\0\0\0\0\0\0\x79\
\xa7\xd8\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xb7\x02\0\
\0\x04\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x01\0\0\0\0\0\0\x0f\x16\0\0\0\0\0\0\x61\
\xa8\xd8\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xb7\x02\0\
\0\x04\0\0\0\xbf\x63\0\0\0\0\0\0\x85\0\0\0\x71\0\0\0\x61\xa1\xd8\xff\0\0\0\0\
\x63\x1a\xd8\xff\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\x22\0\0\0\0\0\
\0\x15\x02\x04\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x22\0\0\0\0\0\
\0\x5d\x12\x26\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xd8\xff\xff\xff\x18\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x55\0\x10\0\0\0\0\0\xbf\
\xa2\0\0\0\0\0\0\x07\x02\0\0\xd8\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\
\xe0\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\x01\0\0\0\x85\
\0\0\0\x02\0\0\0\x15\0\x01\0\0\0\0\0\x55\0\x16\0\xef\xff\xff\xff\xbf\xa2\0\0\0\
\0\0\0\x07\x02\0\0\xd8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\
\0\x01\0\0\0\x15\0\x10\0\0\0\0\0\x79\x02\0\0\0\0\0\0\x15\x02\x0c\0\0\0\0\0\xb7\
\x01\0\0\x10\0\0\0\x1d\x72\x01\0\0\0\0\0\xb7\x01\0\0\x18\0\0\0\xbf\x02\0\0\0\0\
\0\0\x0f\x12\0\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\xdb\x12\0\0\0\0\0\0\xbf\x81\0\0\
\0\0\0\0\x67\x01\0\0\x09\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\0\xdb\
\x10\x08\0\0\0\0\0\x0f\x87\0\0\0\0\0\0\x7b\x70\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\
\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x47\x50\x4c\0\x7b\0\0\0\x05\0\x08\0\x08\0\0\0\x20\0\0\0\
\x2c\0\0\0\x3c\0\0\0\x4b\0\0\0\x53\0\0\0\x5b\0\0\0\x63\0\0\0\x6b\0\0\0\x04\0\
\x08\x01\x51\x04\x08\xd0\x02\x01\x56\0\x04\x08\x88\x03\x02\x7a\0\x04\x90\x03\
\x90\x06\x02\x7a\0\0\x04\x98\x01\xc8\x01\x01\x57\x04\xa0\x02\xf8\x05\x01\x57\0\
\x04\x90\x03\x90\x06\x01\x58\0\x04\xf0\x03\xf8\x03\x01\x51\0\x04\xf8\x03\xc0\
\x04\x01\x50\0\x04\xc0\x04\xf8\x04\x01\x50\0\x04\xf8\x04\x80\x05\x01\x50\0\x01\
\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\
\x17\x8c\x01\x17\0\0\x02\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\
\0\0\x03\x26\0\x49\x13\0\0\x04\x35\0\x49\x13\0\0\x05\x16\0\x49\x13\x03\x25\x3a\
\x0b\x3b\x0b\0\0\x06\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x07\x01\x01\x49\x13\0\0\
\x08\x21\0\x49\x13\x37\x0b\0\0\x09\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x0a\x13\
\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x0b\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\
\x0b\0\0\x0c\x0f\0\x49\x13\0\0\x0d\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x0b\0\0\
\x0e\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\x1c\x0f\0\0\x0f\x15\x01\x49\x13\x27\
\x19\0\0\x10\x05\0\x49\x13\0\0\x11\x0f\0\0\0\x12\x26\0\0\0\x13\x34\0\x03\x25\
\x49\x13\x3a\x0b\x3b\x0b\x1c\x0f\0\0\x14\x04\x01\x49\x13\x03\x25\x0b\x0b\x3a\
\x0b\x3b\x0b\0\0\x15\x28\0\x03\x25\x1c\x0f\0\0\x16\x04\x01\x49\x13\x0b\x0b\x3a\
\x0b\x3b\x05\0\0\x17\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x05\0\0\x18\x2e\x01\x03\
\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x20\x21\x01\0\0\x19\x05\0\x03\x25\x3a\x0b\
\x3b\x0b\x49\x13\0\0\x1a\x34\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x1b\x2e\x01\
\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\
\x19\0\0\x1c\x05\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x1d\x34\0\x02\
\x18\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x1e\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\
\x0b\x49\x13\0\0\x1f\x0b\x01\x11\x1b\x12\x06\0\0\x20\x1d\x01\x31\x13\x11\x1b\
\x12\x06\x58\x0b\x59\x0b\x57\x0b\0\0\x21\x05\0\x02\x22\x31\x13\0\0\x22\x05\0\
\x02\x18\x31\x13\0\0\x23\x34\0\x02\x22\x31\x13\0\0\0\x57\x03\0\0\x05\0\x01\x08\
\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\0\0\0\0\0\x02\x04\x10\x03\0\0\x08\0\0\0\x0c\0\
\0\0\x02\x03\x32\0\0\0\0\x46\x02\xa1\0\x03\x37\0\0\0\x04\x3c\0\0\0\x05\x44\0\0\
\0\x05\x01\x34\x06\x04\x02\x01\x02\x06\x53\0\0\0\0\x47\x02\xa1\x01\x03\x58\0\0\
\0\x04\x5d\0\0\0\x05\x65\0\0\0\x08\x01\x0c\x06\x07\x07\x04\x02\x09\x74\0\0\0\0\
\x75\x02\xa1\x02\x07\x80\0\0\0\x08\x84\0\0\0\x04\0\x06\x0a\x06\x01\x09\x0b\x08\
\x07\x02\x0c\x93\0\0\0\0\x4e\x02\xa1\x03\x0a\x20\0\x49\x0b\x0d\xbc\0\0\0\0\x4a\
\0\x0b\x0f\xd1\0\0\0\0\x4b\x08\x0b\x10\xe2\0\0\0\0\x4c\x10\x0b\x12\xef\0\0\0\0\
\x4d\x18\0\x0c\xc1\0\0\0\x07\xcd\0\0\0\x08\x84\0\0\0\x01\0\x06\x0e\x05\x04\x0c\
\xd6\0\0\0\x07\xcd\0\0\0\x08\x84\0\0\0\x40\0\x0c\xe7\0\0\0\x05\x5d\0\0\0\x11\
\x01\x16\x0c\xf4\0\0\0\x0d\x19\x20\x02\x06\x0b\x13\x1e\x01\0\0\x02\x07\0\x0b\
\x16\x1e\x01\0\0\x02\x08\x08\x0b\x17\x1e\x01\0\0\x02\x09\x10\x0b\x18\x1e\x01\0\
\0\x02\x0a\x18\0\x05\x26\x01\0\0\x15\x01\x10\x06\x14\x07\x08\x0e\x1a\x34\x01\0\
\0\x03\xf7\x0a\x71\x0c\x39\x01\0\0\x0f\x4e\x01\0\0\x10\x52\x01\0\0\x10\x5d\0\0\
\0\x10\x53\x01\0\0\0\x06\x1b\x05\x08\x11\x0c\x58\x01\0\0\x12\x13\x1c\x62\x01\0\
\0\x03\x38\x01\x0c\x67\x01\0\0\x0f\x52\x01\0\0\x10\x52\x01\0\0\x10\x53\x01\0\0\
\0\x13\x1d\x80\x01\0\0\x03\x4e\x02\x0c\x85\x01\0\0\x0f\x4e\x01\0\0\x10\x52\x01\
\0\0\x10\x53\x01\0\0\x10\x53\x01\0\0\x10\x1e\x01\0\0\0\x14\x65\0\0\0\x21\x04\
\x04\x1d\x15\x1e\0\x15\x1f\x01\x15\x20\x02\0\x16\x65\0\0\0\x04\x01\xb9\x05\x15\
\x22\0\x15\x23\x01\0\x16\x65\0\0\0\x04\x01\x96\x82\x15\x24\0\x15\x25\x01\x15\
\x26\x02\x15\x27\x04\0\x0c\xdd\x01\0\0\x0d\x2f\x18\x05\x48\x0b\x28\xfe\x01\0\0\
\x05\x49\0\x0b\x2b\x10\x02\0\0\x05\x4a\x08\x0b\x2e\x65\0\0\0\x05\x4b\x10\0\x17\
\x07\x02\0\0\x2a\x01\xc4\x05\x17\xe7\0\0\0\x29\x01\xc2\x05\x17\x19\x02\0\0\x2d\
\x01\xce\x05\x05\x1e\x01\0\0\x2c\x01\x1a\x0c\x26\x02\0\0\x0d\x30\x18\x05\x42\
\x0b\x28\xfe\x01\0\0\x05\x43\0\x0b\x2b\x10\x02\0\0\x05\x44\x08\x0b\x2e\x65\0\0\
\0\x05\x45\x10\0\x18\x31\x06\x0a\x52\x01\0\0\x19\x32\x06\x0a\x52\x01\0\0\x19\
\x10\x06\x0a\x53\x01\0\0\x19\x33\x06\x0a\x53\x01\0\0\x1a\x34\x06\x0c\x52\x01\0\
\0\x1a\x35\x06\x0d\x4e\x01\0\0\0\x1b\x04\x10\x03\0\0\x01\x5a\x36\0\x51\xcd\0\0\
\0\x1c\0\x39\0\x51\x52\x01\0\0\x1d\x02\x91\x08\x37\0\x53\xf4\0\0\0\x1e\x01\x28\
\0\x56\xe7\0\0\0\x1e\x02\x2b\0\x54\x10\x02\0\0\x1e\x03\x2e\0\x55\xe7\0\0\0\x1e\
\x07\x3b\0\x53\xef\0\0\0\x1f\x05\x68\0\0\0\x1d\x01\x56\x3a\0\x59\xd8\x01\0\0\
\x1f\x06\x38\0\0\0\x1d\x02\x91\0\x38\0\x5a\x10\x02\0\0\0\x1f\x07\x20\0\0\0\x1d\
\x02\x91\0\x38\0\x5b\x65\0\0\0\0\0\x1f\x08\x60\0\0\0\x1d\x01\x56\x3a\0\x5e\x21\
\x02\0\0\x1f\x09\x38\0\0\0\x1d\x02\x91\0\x38\0\x5f\x10\x02\0\0\0\x1f\x0a\x18\0\
\0\0\x1d\x02\x91\0\x38\0\x60\x65\0\0\0\0\0\x20\x47\x02\0\0\x0b\xa0\0\0\0\0\x67\
\x0d\x21\x04\x4f\x02\0\0\x22\x01\x5a\x57\x02\0\0\x22\x03\x91\x08\x9f\x5f\x02\0\
\0\x23\x05\x67\x02\0\0\x23\x06\x6f\x02\0\0\0\0\0\xf4\0\0\0\x05\0\0\0\0\0\0\0\
\x27\0\0\0\x38\0\0\0\x64\0\0\0\x6f\0\0\0\x75\0\0\0\x7a\0\0\0\x83\0\0\0\x90\0\0\
\0\x96\0\0\0\x9e\0\0\0\xa3\0\0\0\xb7\0\0\0\xc0\0\0\0\xc5\0\0\0\xc9\0\0\0\xd5\0\
\0\0\xd9\0\0\0\xdd\0\0\0\xe3\0\0\0\xef\0\0\0\x02\x01\0\0\x08\x01\0\0\x0e\x01\0\
\0\x19\x01\0\0\x20\x01\0\0\x28\x01\0\0\x3e\x01\0\0\x43\x01\0\0\x57\x01\0\0\x6b\
\x01\0\0\x7b\x01\0\0\x89\x01\0\0\x9a\x01\0\0\xad\x01\0\0\xb3\x01\0\0\xb8\x01\0\
\0\xc0\x01\0\0\xcc\x01\0\0\xd6\x01\0\0\xe1\x01\0\0\xe5\x01\0\0\xf4\x01\0\0\xfa\
\x01\0\0\x01\x02\0\0\x05\x02\0\0\x0e\x02\0\0\x18\x02\0\0\x40\x02\0\0\x66\x02\0\
\0\x81\x02\0\0\x85\x02\0\0\x8a\x02\0\0\x8e\x02\0\0\x92\x02\0\0\xac\x02\0\0\xb1\
\x02\0\0\xb5\x02\0\0\xba\x02\0\0\xbe\x02\0\0\x55\x62\x75\x6e\x74\x75\x20\x63\
\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x38\x2e\x31\x2e\x33\
\x20\x28\x31\x75\x62\x75\x6e\x74\x75\x31\x29\0\x62\x69\x6f\x70\x61\x74\x74\x65\
\x72\x6e\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x63\x61\x69\x6e\x69\
\x61\x6f\x2f\x45\x62\x70\x66\x2f\x45\x62\x70\x66\x2f\x6c\x65\x73\x73\x6f\x6e\
\x31\x37\x2d\x62\x69\x6f\x70\x61\x74\x74\x65\x72\x6e\0\x66\x69\x6c\x74\x65\x72\
\x5f\x64\x65\x76\0\x5f\x42\x6f\x6f\x6c\0\x62\x6f\x6f\x6c\0\x74\x61\x72\x67\x5f\
\x64\x65\x76\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\
\x33\x32\0\x4c\x49\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\
\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x63\x6f\x75\x6e\x74\
\x65\x72\x73\0\x74\x79\x70\x65\0\x69\x6e\x74\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\
\x69\x65\x73\0\x6b\x65\x79\0\x75\x33\x32\0\x76\x61\x6c\x75\x65\0\x6c\x61\x73\
\x74\x5f\x73\x65\x63\x74\x6f\x72\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\
\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\x34\0\x62\x79\x74\x65\x73\0\x73\
\x65\x71\x75\x65\x6e\x74\x69\x61\x6c\0\x72\x61\x6e\x64\x6f\x6d\0\x63\x6f\x75\
\x6e\x74\x65\x72\0\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\
\x6b\x65\x72\x6e\x65\x6c\0\x6c\x6f\x6e\x67\0\x62\x70\x66\x5f\x6d\x61\x70\x5f\
\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\0\x62\x70\x66\x5f\x6d\x61\x70\x5f\
\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\0\x42\x50\x46\x5f\x54\x59\x50\x45\
\x5f\x45\x58\x49\x53\x54\x53\0\x42\x50\x46\x5f\x54\x59\x50\x45\x5f\x53\x49\x5a\
\x45\0\x42\x50\x46\x5f\x54\x59\x50\x45\x5f\x4d\x41\x54\x43\x48\x45\x53\0\x62\
\x70\x66\x5f\x74\x79\x70\x65\x5f\x69\x6e\x66\x6f\x5f\x6b\x69\x6e\x64\0\x66\x61\
\x6c\x73\x65\0\x74\x72\x75\x65\0\x42\x50\x46\x5f\x41\x4e\x59\0\x42\x50\x46\x5f\
\x4e\x4f\x45\x58\x49\x53\x54\0\x42\x50\x46\x5f\x45\x58\x49\x53\x54\0\x42\x50\
\x46\x5f\x46\x5f\x4c\x4f\x43\x4b\0\x64\x65\x76\0\x5f\x5f\x6b\x65\x72\x6e\x65\
\x6c\x5f\x64\x65\x76\x5f\x74\0\x64\x65\x76\x5f\x74\0\x73\x65\x63\x74\x6f\x72\0\
\x75\x36\x34\0\x73\x65\x63\x74\x6f\x72\x5f\x74\0\x6e\x72\x5f\x73\x65\x63\x74\
\x6f\x72\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x62\
\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x69\x6f\x6e\x5f\
\x5f\x5f\x78\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\
\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x5f\x5f\
\x5f\x78\0\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x6f\x72\
\x5f\x74\x72\x79\x5f\x69\x6e\x69\x74\0\x6d\x61\x70\0\x69\x6e\x69\x74\0\x76\x61\
\x6c\0\x65\x72\x72\0\x68\x61\x6e\x64\x6c\x65\x5f\x5f\x62\x6c\x6f\x63\x6b\x5f\
\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x7a\x65\x72\x6f\0\x5f\x5f\x72\0\
\x61\x72\x67\x73\0\x63\x74\x78\0\x63\x6f\x75\x6e\x74\x65\x72\x70\0\x64\0\0\0\
\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x68\0\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\xe8\0\0\0\
\0\0\0\0\xf0\0\0\0\0\0\0\0\x30\x01\0\0\0\0\0\0\xd8\x01\0\0\0\0\0\0\0\0\0\x9f\
\xeb\x01\0\x18\0\0\0\0\0\0\0\0\x03\0\0\0\x03\0\0\x7b\x04\0\0\0\0\0\0\0\0\0\x02\
\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\
\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\x02\x08\0\0\0\x19\0\0\0\0\0\0\x08\x09\0\0\0\x1d\0\0\0\0\0\0\x08\
\x0a\0\0\0\x23\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\
\x30\0\0\0\x04\0\0\x04\x20\0\0\0\x38\0\0\0\x0d\0\0\0\0\0\0\0\x44\0\0\0\x0d\0\0\
\0\x40\0\0\0\x4a\0\0\0\x0d\0\0\0\x80\0\0\0\x55\0\0\0\x0d\0\0\0\xc0\0\0\0\x5c\0\
\0\0\0\0\0\x08\x0e\0\0\0\x62\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x04\0\
\0\x04\x20\0\0\0\x75\0\0\0\x01\0\0\0\0\0\0\0\x7a\0\0\0\x05\0\0\0\x40\0\0\0\x86\
\0\0\0\x07\0\0\0\x80\0\0\0\x8a\0\0\0\x0b\0\0\0\xc0\0\0\0\x90\0\0\0\0\0\0\x0e\
\x0f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\
\x99\0\0\0\x11\0\0\0\x9e\0\0\0\x01\0\0\x0c\x12\0\0\0\x68\x01\0\0\x03\0\0\x04\
\x18\0\0\0\x90\x01\0\0\x15\0\0\0\0\0\0\0\x94\x01\0\0\x17\0\0\0\x40\0\0\0\x9b\
\x01\0\0\x0a\0\0\0\x80\0\0\0\xa5\x01\0\0\0\0\0\x08\x16\0\0\0\xab\x01\0\0\0\0\0\
\x08\x08\0\0\0\xba\x01\0\0\0\0\0\x08\x18\0\0\0\xc3\x01\0\0\0\0\0\x08\x0d\0\0\0\
\x4b\x02\0\0\x03\0\0\x04\x18\0\0\0\x90\x01\0\0\x15\0\0\0\0\0\0\0\x94\x01\0\0\
\x17\0\0\0\x40\0\0\0\x9b\x01\0\0\x0a\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\x0a\x1b\0\0\
\0\0\0\0\0\0\0\0\x09\x1c\0\0\0\x39\x04\0\0\0\0\0\x08\x1d\0\0\0\x3e\x04\0\0\0\0\
\0\x01\x01\0\0\0\x08\0\0\x04\x44\x04\0\0\0\0\0\x0e\x1a\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\x0a\x20\0\0\0\0\0\0\0\0\0\0\x09\x09\0\0\0\x4f\x04\0\0\0\0\0\x0e\x1f\0\0\
\0\x01\0\0\0\x58\x04\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\
\0\0\x22\0\0\0\x04\0\0\0\x04\0\0\0\x5d\x04\0\0\0\0\0\x0e\x23\0\0\0\x01\0\0\0\
\x65\x04\0\0\x01\0\0\x0f\0\0\0\0\x10\0\0\0\0\0\0\0\x20\0\0\0\x6b\x04\0\0\x02\0\
\0\x0f\0\0\0\0\x1e\0\0\0\0\0\0\0\x01\0\0\0\x21\0\0\0\0\0\0\0\x04\0\0\0\x73\x04\
\0\0\x01\0\0\x0f\0\0\0\0\x24\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\
\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x75\x33\
\x32\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\
\x63\x6f\x75\x6e\x74\x65\x72\0\x6c\x61\x73\x74\x5f\x73\x65\x63\x74\x6f\x72\0\
\x62\x79\x74\x65\x73\0\x73\x65\x71\x75\x65\x6e\x74\x69\x61\x6c\0\x72\x61\x6e\
\x64\x6f\x6d\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\
\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\
\x74\x72\x69\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x63\x6f\x75\x6e\x74\
\x65\x72\x73\0\x61\x72\x67\x73\0\x68\x61\x6e\x64\x6c\x65\x5f\x5f\x62\x6c\x6f\
\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x2f\x62\x6c\x6f\x63\x6b\x2f\x62\x6c\x6f\x63\x6b\x5f\x72\
\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x2f\x68\x6f\x6d\x65\x2f\x63\x61\x69\
\x6e\x69\x61\x6f\x2f\x45\x62\x70\x66\x2f\x45\x62\x70\x66\x2f\x6c\x65\x73\x73\
\x6f\x6e\x31\x37\x2d\x62\x69\x6f\x70\x61\x74\x74\x65\x72\x6e\x2f\x62\x69\x6f\
\x70\x61\x74\x74\x65\x72\x6e\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x68\x61\
\x6e\x64\x6c\x65\x5f\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\
\x6c\x65\x74\x65\x28\x76\x6f\x69\x64\x20\x2a\x61\x72\x67\x73\x29\0\x09\x73\x74\
\x72\x75\x63\x74\x20\x63\x6f\x75\x6e\x74\x65\x72\x20\x2a\x63\x6f\x75\x6e\x74\
\x65\x72\x70\x2c\x20\x7a\x65\x72\x6f\x20\x3d\x20\x7b\x7d\x3b\0\x74\x72\x61\x63\
\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\
\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x69\x6f\x6e\x5f\x5f\x5f\x78\0\x64\x65\x76\
\0\x73\x65\x63\x74\x6f\x72\0\x6e\x72\x5f\x73\x65\x63\x74\x6f\x72\0\x64\x65\x76\
\x5f\x74\0\x5f\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x64\x65\x76\x5f\x74\0\x73\x65\
\x63\x74\x6f\x72\x5f\x74\0\x75\x36\x34\0\x30\0\x09\x69\x66\x20\x28\x68\x61\x73\
\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x69\x6f\
\x6e\x28\x29\x29\x20\x7b\0\x30\x3a\x31\0\x09\x09\x73\x65\x63\x74\x6f\x72\x20\
\x3d\x20\x42\x50\x46\x5f\x43\x4f\x52\x45\x5f\x52\x45\x41\x44\x28\x63\x74\x78\
\x2c\x20\x73\x65\x63\x74\x6f\x72\x29\x3b\0\x30\x3a\x32\0\x09\x09\x6e\x72\x5f\
\x73\x65\x63\x74\x6f\x72\x20\x3d\x20\x42\x50\x46\x5f\x43\x4f\x52\x45\x5f\x52\
\x45\x41\x44\x28\x63\x74\x78\x2c\x20\x6e\x72\x5f\x73\x65\x63\x74\x6f\x72\x29\
\x3b\0\x30\x3a\x30\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\
\x77\x5f\x62\x6c\x6f\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\
\x5f\x5f\x5f\x78\0\x09\x69\x66\x20\x28\x66\x69\x6c\x74\x65\x72\x5f\x64\x65\x76\
\x20\x26\x26\x20\x74\x61\x72\x67\x5f\x64\x65\x76\x20\x21\x3d\x20\x64\x65\x76\
\x29\0\x2f\x68\x6f\x6d\x65\x2f\x63\x61\x69\x6e\x69\x61\x6f\x2f\x45\x62\x70\x66\
\x2f\x45\x62\x70\x66\x2f\x6c\x65\x73\x73\x6f\x6e\x31\x37\x2d\x62\x69\x6f\x70\
\x61\x74\x74\x65\x72\x6e\x2f\x2e\x2f\x6d\x61\x70\x73\x2e\x62\x70\x66\x2e\x68\0\
\x09\x76\x61\x6c\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\
\x75\x70\x5f\x65\x6c\x65\x6d\x28\x6d\x61\x70\x2c\x20\x6b\x65\x79\x29\x3b\0\x09\
\x69\x66\x20\x28\x76\x61\x6c\x29\0\x09\x65\x72\x72\x20\x3d\x20\x62\x70\x66\x5f\
\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x6d\x61\x70\
\x2c\x20\x6b\x65\x79\x2c\x20\x69\x6e\x69\x74\x2c\x20\x42\x50\x46\x5f\x4e\x4f\
\x45\x58\x49\x53\x54\x29\x3b\0\x09\x69\x66\x20\x28\x65\x72\x72\x20\x26\x26\x20\
\x65\x72\x72\x20\x21\x3d\x20\x2d\x45\x45\x58\x49\x53\x54\x29\0\x09\x72\x65\x74\
\x75\x72\x6e\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\
\x65\x6c\x65\x6d\x28\x6d\x61\x70\x2c\x20\x6b\x65\x79\x29\x3b\0\x09\x69\x66\x20\
\x28\x21\x63\x6f\x75\x6e\x74\x65\x72\x70\x29\0\x09\x69\x66\x20\x28\x63\x6f\x75\
\x6e\x74\x65\x72\x70\x2d\x3e\x6c\x61\x73\x74\x5f\x73\x65\x63\x74\x6f\x72\x29\
\x20\x7b\0\x09\x09\x69\x66\x20\x28\x63\x6f\x75\x6e\x74\x65\x72\x70\x2d\x3e\x6c\
\x61\x73\x74\x5f\x73\x65\x63\x74\x6f\x72\x20\x3d\x3d\x20\x73\x65\x63\x74\x6f\
\x72\x29\0\x09\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\
\x64\x5f\x61\x64\x64\x28\x26\x63\x6f\x75\x6e\x74\x65\x72\x70\x2d\x3e\x62\x79\
\x74\x65\x73\x2c\x20\x6e\x72\x5f\x73\x65\x63\x74\x6f\x72\x20\x2a\x20\x35\x31\
\x32\x29\x3b\0\x09\x63\x6f\x75\x6e\x74\x65\x72\x70\x2d\x3e\x6c\x61\x73\x74\x5f\
\x73\x65\x63\x74\x6f\x72\x20\x3d\x20\x73\x65\x63\x74\x6f\x72\x20\x2b\x20\x6e\
\x72\x5f\x73\x65\x63\x74\x6f\x72\x3b\0\x7d\0\x62\x6f\x6f\x6c\0\x5f\x42\x6f\x6f\
\x6c\0\x66\x69\x6c\x74\x65\x72\x5f\x64\x65\x76\0\x74\x61\x72\x67\x5f\x64\x65\
\x76\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\
\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\x9f\xeb\x01\0\
\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x3c\x02\0\0\x50\x02\0\0\x7c\0\0\0\x08\0\
\0\0\xb8\0\0\0\x01\0\0\0\0\0\0\0\x13\0\0\0\x10\0\0\0\xb8\0\0\0\x23\0\0\0\0\0\0\
\0\xdb\0\0\0\x18\x01\0\0\0\x44\x01\0\x10\0\0\0\xdb\0\0\0\x42\x01\0\0\x1c\x4c\
\x01\0\x38\0\0\0\xdb\0\0\0\xc9\x01\0\0\x06\x60\x01\0\x60\0\0\0\xdb\0\0\0\0\0\0\
\0\0\0\0\0\x68\0\0\0\xdb\0\0\0\xef\x01\0\0\x0c\x68\x01\0\x90\0\0\0\xdb\0\0\0\
\xef\x01\0\0\x0c\x68\x01\0\xa0\0\0\0\xdb\0\0\0\0\0\0\0\0\0\0\0\xa8\0\0\0\xdb\0\
\0\0\x1a\x02\0\0\x0f\x6c\x01\0\xe8\0\0\0\xdb\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\
\xdb\0\0\0\xef\x01\0\0\x0c\x7c\x01\0\x18\x01\0\0\xdb\0\0\0\xef\x01\0\0\x0c\x7c\
\x01\0\x28\x01\0\0\xdb\0\0\0\0\0\0\0\0\0\0\0\x30\x01\0\0\xdb\0\0\0\x1a\x02\0\0\
\x0f\x80\x01\0\x50\x01\0\0\xdb\0\0\0\0\0\0\0\0\0\0\0\x90\x01\0\0\xdb\0\0\0\x71\
\x02\0\0\x06\x90\x01\0\xa8\x01\0\0\xdb\0\0\0\x71\x02\0\0\x11\x90\x01\0\xb0\x01\
\0\0\xdb\0\0\0\x71\x02\0\0\x14\x90\x01\0\xc8\x01\0\0\xdb\0\0\0\x71\x02\0\0\x06\
\x90\x01\0\xd8\x01\0\0\x95\x02\0\0\0\0\0\0\0\0\0\0\xe0\x01\0\0\x95\x02\0\0\xce\
\x02\0\0\x08\x3c\0\0\xf8\x01\0\0\x95\x02\0\0\xf4\x02\0\0\x06\x40\0\0\x08\x02\0\
\0\x95\x02\0\0\xfe\x02\0\0\x08\x4c\0\0\x40\x02\0\0\x95\x02\0\0\x37\x03\0\0\x0a\
\x50\0\0\x58\x02\0\0\x95\x02\0\0\x53\x03\0\0\x09\x5c\0\0\x78\x02\0\0\xdb\0\0\0\
\x7a\x03\0\0\x06\xa0\x01\0\x80\x02\0\0\xdb\0\0\0\x8a\x03\0\0\x10\xa8\x01\0\x88\
\x02\0\0\xdb\0\0\0\x8a\x03\0\0\x06\xa8\x01\0\x98\x02\0\0\xdb\0\0\0\xa8\x03\0\0\
\x07\xac\x01\0\xa8\x02\0\0\xdb\0\0\0\0\0\0\0\0\0\0\0\xc8\x02\0\0\xdb\0\0\0\xcf\
\x03\0\0\x34\xbc\x01\0\xd8\x02\0\0\xdb\0\0\0\xcf\x03\0\0\x2a\xbc\x01\0\xe8\x02\
\0\0\xdb\0\0\0\xcf\x03\0\0\x03\xbc\x01\0\xf0\x02\0\0\xdb\0\0\0\x0a\x04\0\0\x21\
\xc4\x01\0\xf8\x02\0\0\xdb\0\0\0\x0a\x04\0\0\x18\xc4\x01\0\0\x03\0\0\xdb\0\0\0\
\x37\x04\0\0\x01\xcc\x01\0\x10\0\0\0\xb8\0\0\0\x07\0\0\0\x30\0\0\0\x14\0\0\0\
\xc7\x01\0\0\x08\0\0\0\x40\0\0\0\x14\0\0\0\xeb\x01\0\0\0\0\0\0\x78\0\0\0\x14\0\
\0\0\x16\x02\0\0\0\0\0\0\xb8\0\0\0\x14\0\0\0\x47\x02\0\0\0\0\0\0\xc8\0\0\0\x19\
\0\0\0\xeb\x01\0\0\0\0\0\0\0\x01\0\0\x19\0\0\0\x16\x02\0\0\0\0\0\0\x40\x01\0\0\
\x19\0\0\0\x47\x02\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\
\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x03\0\0\0\0\0\0\x97\x01\0\
\0\x05\0\x08\0\xbd\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\
\0\x01\x01\x01\x1f\x03\0\0\0\0\x2c\0\0\0\x2e\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\
\x07\x3f\0\0\0\0\xfd\xb2\x5f\xf2\x28\x66\x03\x22\x12\x32\x3c\x51\xdf\x9f\x26\
\xa5\x50\0\0\0\x01\x19\xb5\x6b\xd2\x59\x66\xf1\x7c\x35\xe4\x81\x76\x73\x9f\x1b\
\xa6\x5a\0\0\0\x01\xaa\x3c\x08\x4d\x55\xc1\xda\x39\x0d\xff\x9e\x71\x3a\x9c\x55\
\x34\x67\0\0\0\x02\x09\xcf\xcd\x71\x69\xc2\x4b\xec\x44\x8f\x30\x58\x2e\x8c\x6d\
\xb9\x79\0\0\0\x02\x4d\x57\xa6\x01\x03\x1b\x70\xe8\xe2\x21\xd8\x5d\x16\x7b\xea\
\xcb\x89\0\0\0\x01\x87\xab\x88\x83\x3f\x4a\x95\xae\x02\x6d\xea\x79\xd6\x9a\x78\
\xc2\x9a\0\0\0\x01\x0b\xe6\x69\x97\x3a\x0f\x48\x9d\xbe\x51\x57\x59\x32\x3f\x66\
\xf9\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\xd1\0\x01\x05\x1c\x0a\x2f\x05\x06\x5d\
\x06\x03\xa8\x7f\x20\x05\x0c\x06\x03\xda\0\x58\x06\x03\xa6\x7f\x2e\x03\xda\0\
\x3c\x03\xa6\x7f\x20\x05\x0f\x06\x03\xdb\0\x2e\x06\x03\xa5\x7f\x2e\x05\x0c\x06\
\x03\xdf\0\x74\x06\x03\xa1\x7f\x2e\x03\xdf\0\x3c\x03\xa1\x7f\x20\x05\x0f\x06\
\x03\xe0\0\x2e\x06\x03\xa0\x7f\x2e\x05\x06\x06\x03\xe4\0\x9e\x05\x11\x06\x3c\
\x05\x14\x20\x05\x06\x3c\x03\x9c\x7f\x20\x04\x06\x05\x08\x06\x03\x0f\x2e\x05\
\x06\x3d\x06\x03\x70\x20\x05\x08\x06\x03\x13\x20\x05\x0a\x75\x06\x03\x6c\x2e\
\x05\x09\x06\x03\x17\x20\x04\0\x05\x06\x03\xd1\0\x4a\x05\x10\x22\x05\x06\x06\
\x20\x03\x96\x7f\x20\x05\x07\x06\x03\xeb\0\x20\x06\x03\x95\x7f\x20\x05\x34\x06\
\x03\xef\0\x58\x05\x2a\x06\x2e\x05\x03\x2e\x05\x21\x06\x22\x05\x18\x06\x20\x05\
\x01\x06\x22\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x63\x61\x69\x6e\x69\x61\
\x6f\x2f\x45\x62\x70\x66\x2f\x45\x62\x70\x66\x2f\x6c\x65\x73\x73\x6f\x6e\x31\
\x37\x2d\x62\x69\x6f\x70\x61\x74\x74\x65\x72\x6e\0\x2e\0\x2f\x75\x73\x72\x2f\
\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\x62\x69\x6f\x70\x61\x74\x74\x65\
\x72\x6e\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\0\x62\
\x69\x6f\x70\x61\x74\x74\x65\x72\x6e\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\
\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x62\x70\x66\x5f\x63\x6f\x72\x65\x5f\x72\
\x65\x61\x64\x2e\x68\0\x63\x6f\x72\x65\x2e\x66\x69\x78\x65\x73\x2e\x62\x70\x66\
\x2e\x68\0\x6d\x61\x70\x73\x2e\x62\x70\x66\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x1f\x01\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\x01\0\0\0\0\x03\0\
\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x76\x01\0\0\0\0\x03\0\x48\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x67\x01\0\0\0\0\x03\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\
\x01\0\0\0\0\x03\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x59\x01\0\0\0\0\x03\0\x80\
\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x01\0\0\0\0\x03\0\x50\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x7d\x01\0\0\0\0\x03\0\xf0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\x01\
\0\0\0\0\x03\0\xa8\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x15\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb5\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x10\x03\0\0\0\0\0\0\x0f\0\0\0\x11\0\x05\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x1a\0\0\0\x11\0\x05\0\x04\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\x5d\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x51\
\x01\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\x01\
\0\0\0\x14\0\0\0\xb0\x01\0\0\0\0\0\0\x01\0\0\0\x15\0\0\0\xe0\x01\0\0\0\0\0\0\
\x01\0\0\0\x16\0\0\0\x20\x02\0\0\0\0\0\0\x01\0\0\0\x16\0\0\0\x60\x02\0\0\0\0\0\
\0\x01\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x11\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x1f\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x10\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x18\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x20\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x28\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x30\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x38\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x40\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x48\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x50\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x58\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x60\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x68\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x70\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x74\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x78\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x7c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x80\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x84\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x88\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x8c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x90\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x94\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x98\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x9c\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xa0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xa4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xa8\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xac\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xb0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xb4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xb8\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xbc\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xc0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xc4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xc8\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xcc\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xd0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xd4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xd8\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xdc\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xe0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xe4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xe8\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xec\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xf0\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xf4\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\
\x02\0\0\0\x14\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x15\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x17\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x16\0\0\0\x28\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x30\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x38\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x48\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x58\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\xd4\x02\0\0\0\0\0\0\
\x04\0\0\0\x16\0\0\0\xec\x02\0\0\0\0\0\0\x03\0\0\0\x14\0\0\0\xf8\x02\0\0\0\0\0\
\0\x03\0\0\0\x15\0\0\0\x10\x03\0\0\0\0\0\0\x04\0\0\0\x17\0\0\0\x2c\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xd0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xe0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xf0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x10\x01\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x20\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x30\x01\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\x01\0\0\0\0\
\0\0\x04\0\0\0\x02\0\0\0\x60\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\x01\0\0\0\
\0\0\0\x04\0\0\0\x02\0\0\0\x80\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\x01\0\0\
\0\0\0\0\x04\0\0\0\x02\0\0\0\xa0\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xb0\x01\0\
\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xc0\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xd0\x01\
\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xe0\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xf0\
\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\0\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x10\
\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x20\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\
\x30\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x40\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\
\0\x50\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\
\0\0\x7c\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x8c\x02\0\0\0\0\0\0\x04\0\0\0\x02\
\0\0\0\x9c\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xac\x02\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\xbc\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xcc\x02\0\0\0\0\0\0\x04\0\0\
\0\x02\0\0\0\xdc\x02\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\
\0\x10\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\
\x12\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\
\x12\0\0\0\x36\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x4b\0\0\0\0\0\0\0\x03\0\0\0\
\x12\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x75\0\0\0\0\0\0\0\x03\0\0\0\
\x12\0\0\0\x8a\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x9f\0\0\0\0\0\0\0\x03\0\0\0\
\x12\0\0\0\xb4\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\xce\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x13\x14\x15\x16\x17\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\
\x65\x76\0\x66\x69\x6c\x74\x65\x72\x5f\x64\x65\x76\0\x74\x61\x72\x67\x5f\x64\
\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\
\x74\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\x72\
\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\
\x73\0\x63\x6f\x75\x6e\x74\x65\x72\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x64\x65\x62\
\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\
\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\
\x5f\x61\x64\x64\x72\x73\x69\x67\0\x68\x61\x6e\x64\x6c\x65\x5f\x5f\x62\x6c\x6f\
\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x2e\x72\x65\x6c\x74\
\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x62\x6c\x6f\x63\x6b\x2f\x62\x6c\x6f\
\x63\x6b\x5f\x72\x71\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x62\x69\x6f\x70\
\x61\x74\x74\x65\x72\x6e\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\
\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\
\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x39\0\x4c\
\x42\x42\x30\x5f\x38\0\x4c\x42\x42\x30\x5f\x35\0\x4c\x42\x42\x30\x5f\x31\x34\0\
\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\x5f\x31\x33\0\x4c\x42\x42\x30\x5f\
\x32\0\x4c\x42\x42\x30\x5f\x31\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x30\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x3d\x25\0\0\0\0\0\0\x94\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x23\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd3\0\
\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x10\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcf\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x1c\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x40\x01\0\0\x01\0\0\0\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x03\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x66\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x58\x03\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xf6\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x78\x03\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x36\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7c\x03\0\0\0\0\
\0\0\x7f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\x03\0\0\0\0\0\0\xac\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9b\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa7\x05\0\0\0\0\0\0\x5b\x03\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x97\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xa8\x1c\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x0a\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4a\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x02\x09\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x46\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\
\x1c\0\0\0\0\0\0\xc0\x03\0\0\0\0\0\0\x1b\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\
\0\0\0\0\0\0\0\x6c\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfa\x09\0\
\0\0\0\0\0\xc7\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\x8b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc1\x0c\0\0\0\0\0\0\
\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x20\0\0\0\0\0\0\xc0\0\0\0\0\0\
\0\0\x1b\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4c\x01\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2c\x0d\0\0\0\0\0\0\x93\x07\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x01\0\0\x09\0\0\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x21\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1b\0\0\0\x11\
\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2d\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xc0\x14\0\0\0\0\0\0\xec\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb8\x21\0\0\0\0\0\0\xb0\x02\0\0\0\0\0\0\x1b\0\0\0\x13\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x12\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb0\x17\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x0e\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x24\0\0\
\0\0\0\0\x20\0\0\0\0\0\0\0\x1b\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x02\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x17\0\0\0\0\0\0\
\x9b\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfe\0\0\
\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x24\0\0\0\0\0\0\xb0\0\0\0\0\
\0\0\0\x1b\0\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x77\0\0\0\x01\0\
\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x73\x19\0\0\0\0\0\0\xa5\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xa7\0\0\0\x03\x4c\xff\x6f\0\
\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x38\x25\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\x1b\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x01\0\0\x02\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x18\x1a\0\0\0\0\0\0\x40\x02\0\0\0\0\0\0\x01\0\0\0\x13\0\0\
\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct biopattern *biopattern::open(const struct bpf_object_open_opts *opts) { return biopattern__open_opts(opts); }
struct biopattern *biopattern::open_and_load() { return biopattern__open_and_load(); }
int biopattern::load(struct biopattern *skel) { return biopattern__load(skel); }
int biopattern::attach(struct biopattern *skel) { return biopattern__attach(skel); }
void biopattern::detach(struct biopattern *skel) { biopattern__detach(skel); }
void biopattern::destroy(struct biopattern *skel) { biopattern__destroy(skel); }
const void *biopattern::elf_bytes(size_t *sz) { return biopattern__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
biopattern__assert(struct biopattern *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->rodata->filter_dev) == 1, "unexpected size of 'filter_dev'");
	_Static_assert(sizeof(s->rodata->targ_dev) == 4, "unexpected size of 'targ_dev'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __BIOPATTERN_SKEL_H__ */