/*
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com> 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>

#include <linux/livepatch.h>

#include "kpatch-patch.h"

/*
 * There are quite a few similar structures at play in this file:
 * - livepatch.h structs prefixed with klp_*
 * - kpatch-patch.h structs prefixed with kpatch_patch_*
 * - local scaffolding structs prefixed with patch_*
 *
 * The naming of the struct variables follows this convention:
 * - livepatch struct being with "l" (e.g. lfunc)
 * - kpatch_patch structs being with "k" (e.g. kfunc)
 * - local scaffolding structs have no prefix (e.g. func)
 *
 *  The program reads in kpatch_patch structures, arranges them into the
 *  scaffold structures, then creates a livepatch structure suitable for
 *  registration with the livepatch kernel API.  The scaffold structs only
 *  exist to allow the construction of the klp_patch struct.  Once that is
 *  done, the scaffold structs are no longer needed.
 */

struct klp_patch *lpatch;

static LIST_HEAD(patch_objects);
static LIST_HEAD(patch_reloc_secs);

static int patch_objects_nr;
struct patch_object {
	struct list_head list;
	struct list_head funcs;
	struct list_head reloc_secs;
	const char *name;
	int funcs_nr;
};

struct patch_func {
	struct list_head list;
	struct kpatch_patch_func *kfunc;
};

/* For tagged sections named __klp_rela_objname.kpatch.objname */
static char *klp_extract_objname(char *name)
{
	char *buf, *ptr, *objname;

	if (strncmp(name, "__klp_rela", 10))
		goto error;

	buf = kstrdup(name, GFP_KERNEL);
	if (!buf)
		goto error;

	ptr = strchr(buf, '.');
	if (!ptr)
		goto error;
	*(ptr) = '\0';

	ptr = strrchr(buf, '_');
	if (!ptr)
		goto error;
	ptr++;

	objname = kstrdup(ptr, GFP_KERNEL);

	kfree(buf);
	return objname;

error:
	return NULL;
}


static struct patch_object *patch_alloc_new_object(const char *name)
{
	struct patch_object *object;

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;
	INIT_LIST_HEAD(&object->funcs);
	INIT_LIST_HEAD(&object->reloc_secs);
	if (strcmp(name, "vmlinux"))
		object->name = name;
	list_add(&object->list, &patch_objects);
	patch_objects_nr++;
	return object;
}

static struct patch_object *patch_find_object_by_name(const char *name)
{
	struct patch_object *object;

	list_for_each_entry(object, &patch_objects, list)
		if ((!strcmp(name, "vmlinux") && !object->name) ||
		    (object->name && !strcmp(object->name, name)))
			return object;
	return patch_alloc_new_object(name);
}

static int patch_add_func_to_object(struct kpatch_patch_func *kfunc)
{
	struct patch_func *func;
	struct patch_object *object;

	func = kzalloc(sizeof(*func), GFP_KERNEL);
	if (!func)
		return -ENOMEM;
	INIT_LIST_HEAD(&func->list);
	func->kfunc = kfunc;

	object = patch_find_object_by_name(kfunc->objname);
	if (!object) {
		kfree(func);
		return -ENOMEM;
	}
	list_add(&func->list, &object->funcs);
	object->funcs_nr++;
	return 0;
}

static void patch_free_scaffold(void) {
	struct patch_func *func, *safefunc;
	struct patch_object *object, *safeobject;

	list_for_each_entry_safe(object, safeobject, &patch_objects, list) {
		list_for_each_entry_safe(func, safefunc,
		                         &object->funcs, list) {
			list_del(&func->list);
			kfree(func);
		}
		/* note: reloc secs already removed from object->reloc_secs */
		list_del(&object->list);
		kfree(object);
	}
}

static void patch_free_livepatch(struct klp_patch *patch)
{
	struct klp_object *object;
	struct klp_reloc_sec *reloc_sec, *safe_reloc_sec;

	if (patch) {
	    for (object = patch->objs; object && object->funcs; object++) {
		if (object->funcs)
			kfree(object->funcs);
		list_for_each_entry_safe(reloc_sec, safe_reloc_sec,
					 &object->reloc_secs, list) {
			list_del(&reloc_sec->list);
		    }
	    }
	    /* reloc secs already removed from object->reloc_secs */
	    if (patch->objs)
		kfree(patch->objs);
	    kfree(patch);
	}
}

extern struct kpatch_patch_func __kpatch_funcs[], __kpatch_funcs_end[];

static int __init patch_init(void)
{
	struct kpatch_patch_func *kfunc;
	struct klp_object *lobjects, *lobject;
	struct klp_func *lfuncs, *lfunc;
	struct klp_reloc_sec *lreloc_sec, *safe_reloc_sec, *reloc_sec;
	struct patch_object *object;
	struct patch_func *func;
	int ret = 0, i, j;

	struct load_info *info;

	info = THIS_MODULE->info;

	/* organize functions by object in scaffold */
	for (kfunc = __kpatch_funcs;
	     kfunc != __kpatch_funcs_end;
	     kfunc++) {
		ret = patch_add_func_to_object(kfunc);
		if (ret)
			goto out;
	}

	for (i = 1; i < info->hdr->e_shnum; i++) {
		if (info->sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH) {
			reloc_sec = kzalloc(sizeof(struct klp_reloc_sec),
					  GFP_KERNEL);
			if (!reloc_sec)
				return -ENOMEM;

			reloc_sec->name = kstrdup(info->secstrings +
						info->sechdrs[i].sh_name,
						GFP_KERNEL);
			if (!reloc_sec->name)
				return -ENOMEM;

			reloc_sec->objname = klp_extract_objname(reloc_sec->name);
			if (!reloc_sec->objname)
				return -EINVAL; /* badly formatted name? */

			reloc_sec->index = i;
			list_add(&reloc_sec->list, &patch_reloc_secs);
		}
	}

	/* sort reloc_secs into their respective objects */
	list_for_each_entry_safe(lreloc_sec, safe_reloc_sec,
				 &patch_reloc_secs, list) {
		object = patch_find_object_by_name(lreloc_sec->objname);
		if (!object)
			return -ENOMEM;
		list_del(&lreloc_sec->list);
		list_add(&lreloc_sec->list, &object->reloc_secs);
	}

	/* past this point, only possible return code is -ENOMEM */
	ret = -ENOMEM;

	/* allocate and fill livepatch structures */
	lpatch = kzalloc(sizeof(*lpatch), GFP_KERNEL);
	if (!lpatch)
		goto out;

	lobjects = kzalloc(sizeof(*lobjects) * (patch_objects_nr+1),
			   GFP_KERNEL);
	if (!lobjects)
		goto out;
	lpatch->mod = THIS_MODULE;
	lpatch->objs = lobjects;

	i = 0;
	list_for_each_entry(object, &patch_objects, list) {
		lobject = &lobjects[i];
		lobject->name = object->name;
		lfuncs = kzalloc(sizeof(struct klp_func) *
		                 (object->funcs_nr+1), GFP_KERNEL);
		if (!lfuncs)
			goto out;
		lobject->funcs = lfuncs;
		j = 0;
		list_for_each_entry(func, &object->funcs, list) {
			lfunc = &lfuncs[j];
			lfunc->old_name = func->kfunc->name;
			lfunc->new_func = (void *)func->kfunc->new_addr;
			lfunc->old_addr = func->kfunc->old_addr;
			j++;
		}

		INIT_LIST_HEAD(&lobject->reloc_secs);

		list_for_each_entry_safe(lreloc_sec, safe_reloc_sec,
					 &object->reloc_secs, list) {
		    /* move from object to lobject list */
		    list_del(&lreloc_sec->list);
		    list_add(&lreloc_sec->list, &lobject->reloc_secs);
		}

		i++;
	}

	/*
	 * Once the patch structure that the live patching API expects
	 * has been built, we can release the scaffold structure.
	 */
	patch_free_scaffold();

	ret = klp_register_patch(lpatch);
	if (ret) {
		patch_free_livepatch(lpatch);
		return ret;
	}

	ret = klp_enable_patch(lpatch);
	if (ret) {
		WARN_ON(klp_unregister_patch(lpatch));
		patch_free_livepatch(lpatch);
		return ret;
	}

	return 0;
out:
	patch_free_livepatch(lpatch);
	patch_free_scaffold();
	return ret;
}

static void __exit patch_exit(void)
{
	struct module *mod;

	mod = THIS_MODULE;

	if (mod->info) {
		vfree(mod->info->hdr);
		kfree(mod->info);
	}

	WARN_ON(klp_unregister_patch(lpatch));
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
