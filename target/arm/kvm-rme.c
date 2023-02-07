/*
 * QEMU Arm RME support
 *
 * Copyright Linaro 2022
 */

#include "qemu/osdep.h"

#include "exec/confidential-guest-support.h"
#include "hw/boards.h"
#include "hw/core/cpu.h"
#include "hw/loader.h"
#include "kvm_arm.h"
#include "migration/blocker.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "sysemu/kvm.h"
#include "sysemu/runstate.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

#define RME_PAGE_SIZE qemu_real_host_page_size()

#define RME_MAX_CFG         1

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;
    uint8_t *personalization_value;
};

typedef struct {
    hwaddr base;
    hwaddr len;
    /* Populate guest RAM with data, or only initialize the IPA range */
    bool populate;
} RmeRamRegion;

static RmeGuest *rme_guest;

bool kvm_arm_rme_enabled(void)
{
    return !!rme_guest;
}

static int rme_create_rd(Error **errp)
{
    int ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                                KVM_CAP_ARM_RME_CREATE_RD);

    if (ret) {
        error_setg_errno(errp, -ret, "RME: failed to create Realm Descriptor");
    }
    return ret;
}

static int rme_configure_one(RmeGuest *guest, uint32_t cfg, Error **errp)
{
    int ret;
    const char *cfg_str;
    struct kvm_cap_arm_rme_config_item args = {
        .cfg = cfg,
    };

    switch (cfg) {
    case KVM_CAP_ARM_RME_CFG_RPV:
        if (!guest->personalization_value) {
            return 0;
        }
        memcpy(args.rpv, guest->personalization_value, KVM_CAP_ARM_RME_RPV_SIZE);
        cfg_str = "personalization value";
        break;
    default:
        g_assert_not_reached();
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_CONFIG_REALM, (intptr_t)&args);
    if (ret) {
        error_setg_errno(errp, -ret, "RME: failed to configure %s", cfg_str);
    }
    return ret;
}

static int rme_configure(void)
{
    int ret;
    int cfg;

    for (cfg = 0; cfg < RME_MAX_CFG; cfg++) {
        ret = rme_configure_one(rme_guest, cfg, &error_abort);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static void rme_init_ipa_realm(gpointer data, gpointer unused)
{
    int ret;
    const RmeRamRegion *region = data;
    struct kvm_cap_arm_rme_init_ipa_args init_args = {
        .init_ipa_base = region->base,
        .init_ipa_size = region->len,
    };

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_INIT_IPA_REALM,
                            (intptr_t)&init_args);
    if (ret) {
        error_report("RME: failed to initialize GPA range (0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx"): %s",
                     region->base, region->len, strerror(-ret));
        exit(1);
    }
}

static void rme_populate_realm(gpointer data, gpointer unused)
{
    int ret;
    const RmeRamRegion *region = data;
    struct kvm_cap_arm_rme_populate_realm_args populate_args = {
        .populate_ipa_base = region->base,
        .populate_ipa_size = region->len,
        .flags = KVM_ARM_RME_POPULATE_FLAGS_MEASURE,
    };

    if (!region->populate) {
        return;
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_POPULATE_REALM,
                            (intptr_t)&populate_args);
    if (ret) {
        error_report("RME: failed to populate realm (0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx"): %s",
                     region->base, region->len, strerror(-ret));
        exit(1);
    }
}

static void rme_vm_state_change(void *opaque, bool running, RunState state)
{
    int ret;
    CPUState *cs;

    if (!running) {
        /* TODO: handle re-start */
        return;
    }

    ret = rme_configure();
    if (ret) {
        return;
    }

    ret = rme_create_rd(&error_abort);
    if (ret) {
        return;
    }

    /*
     * First initialize all IPA state. Some regions can overlap
     */
    g_slist_foreach(rme_guest->ram_regions, rme_init_ipa_realm, NULL);
    g_slist_foreach(rme_guest->ram_regions, rme_populate_realm, NULL);
    g_slist_free_full(g_steal_pointer(&rme_guest->ram_regions), g_free);

    /*
     * Now that do_cpu_reset() initialized the boot PC and
     * kvm_cpu_synchronize_post_reset() registered it, we can finalize the REC.
     */
    CPU_FOREACH(cs) {
        ret = kvm_arm_vcpu_finalize(cs, KVM_ARM_VCPU_REC);
        if (ret) {
            error_report("RME: failed to finalize vCPU: %s", strerror(-ret));
            exit(1);
        }
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_ACTIVATE_REALM);
    if (ret) {
        error_report("RME: failed to activate realm: %s", strerror(-ret));
        exit(1);
    }
}

static gint rme_compare_ram_regions(gconstpointer a, gconstpointer b)
{
        const RmeRamRegion *ra = a;
        const RmeRamRegion *rb = b;

        g_assert(ra->base != rb->base);
        return ra->base < rb->base ? -1 : 1;
}

static void rme_add_ram_region(hwaddr base, hwaddr len, bool populate)
{
    RmeRamRegion *region;

    region = g_new0(RmeRamRegion, 1);
    region->base = QEMU_ALIGN_DOWN(base, RME_PAGE_SIZE);
    region->len = QEMU_ALIGN_UP(len, RME_PAGE_SIZE);
    region->populate = populate;

    /*
     * The Realm Initial Measurement (RIM) depends on the order in which we
     * initialize and populate the RAM regions. To help keep the RIM stable
     * across machine versions, sort regions by address.
     */
    rme_guest->ram_regions = g_slist_insert_sorted(rme_guest->ram_regions,
                                                   region,
                                                   rme_compare_ram_regions);
}

static void rme_rom_load_notify(Notifier *notifier, void *data)
{
    RomLoaderNotify *rom = data;

    rme_add_ram_region(rom->addr, rom->max_len, /* populate */ true);
}

int kvm_arm_rme_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    static Error *rme_mig_blocker;

    if (!rme_guest) {
        return -ENODEV;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_ARM_RME)) {
        error_setg(errp, "KVM does not support RME");
        return -ENODEV;
    }

    error_setg(&rme_mig_blocker, "RME: migration is not implemented");
    migrate_add_blocker(&rme_mig_blocker, &error_fatal);

    /*
     * The realm activation is done last, when the VM starts, after all images
     * have been loaded and all vcpus finalized.
     */
    qemu_add_vm_change_state_handler(rme_vm_state_change, NULL);

    rme_guest->rom_load_notifier.notify = rme_rom_load_notify;
    rom_add_load_notifier(&rme_guest->rom_load_notifier);

    cgs->ready = true;
    return 0;
}

/*
 * kvm_arm_rme_init_guest_ram - Initialize a Realm IPA range
 */
void kvm_arm_rme_init_guest_ram(hwaddr base, size_t size)
{
    if (rme_guest) {
        rme_add_ram_region(base, size, /* populate */ false);
    }
}

int kvm_arm_rme_vcpu_init(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);

    if (rme_guest) {
        cpu->kvm_rme = true;
    }
    return 0;
}

int kvm_arm_rme_vm_type(MachineState *ms)
{
    if (rme_guest) {
        return KVM_VM_TYPE_ARM_REALM;
    }
    return 0;
}

static char *rme_get_rpv(Object *obj, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);
    GString *s;
    char *out;
    int i;

    if (!guest->personalization_value) {
        return NULL;
    }

    s = g_string_sized_new(KVM_CAP_ARM_RME_RPV_SIZE * 2 + 1);

    for (i = KVM_CAP_ARM_RME_RPV_SIZE - 1; i >= 0; i--) {
        g_string_append_printf(s, "%02x", guest->personalization_value[i]);
    }

    out = s->str;
    g_string_free(s, /* free_segment */ false);
    return out;
}

static void rme_set_rpv(Object *obj, const char *value, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);
    size_t in_len = strlen(value);
    uint8_t *out;
    int ret;

    g_free(guest->personalization_value);
    guest->personalization_value = out = g_malloc0(KVM_CAP_ARM_RME_RPV_SIZE);

    /* Two chars per byte */
    if (in_len > KVM_CAP_ARM_RME_RPV_SIZE * 2) {
        error_setg(errp, "Realm Personalization Value is too large");
        return;
    }

    /*
     * Parse as big-endian hexadecimal number (most significant byte on the
     * left), store little-endian, zero-padded on the right.
     */
    while (in_len) {
        /*
         * Do the lower nibble first to catch invalid inputs such as '2z', and
         * to handle the last char.
         */
        in_len--;
        ret = sscanf(value + in_len, "%1hhx", out);
        if (ret != 1) {
            error_setg(errp, "Invalid Realm Personalization Value");
            return;
        }
        if (!in_len) {
            break;
        }
        in_len--;
        ret = sscanf(value + in_len, "%2hhx", out++);
        if (ret != 1) {
            error_setg(errp, "Invalid Realm Personalization Value");
            return;
        }
    }
}

static void rme_guest_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "personalization-value", rme_get_rpv,
                                  rme_set_rpv);
    object_class_property_set_description(oc, "personalization-value",
            "Realm personalization value (512-bit hexadecimal number)");
}

static void rme_guest_instance_init(Object *obj)
{
    if (rme_guest) {
        error_report("a single instance of RmeGuest is supported");
        exit(1);
    }
    rme_guest = RME_GUEST(obj);
}

static const TypeInfo rme_guest_info = {
    .parent = TYPE_CONFIDENTIAL_GUEST_SUPPORT,
    .name = TYPE_RME_GUEST,
    .instance_size = sizeof(struct RmeGuest),
    .instance_init = rme_guest_instance_init,
    .class_init = rme_guest_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void rme_register_types(void)
{
    type_register_static(&rme_guest_info);
}

type_init(rme_register_types);
