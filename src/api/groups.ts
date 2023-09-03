import validator from 'validator';

import privileges from '../privileges';
import events from '../events';
import groups from '../groups';
import user from '../user';
import meta from '../meta';
import notifications from '../notifications';
import slugify from '../slugify';

interface GroupsAPI {
    create: (caller: Caller, data: Data) => Promise<GroupData>
    update: (caller: Caller, data: Data) => Promise<GroupData>
    delete: (caller: Caller, data: Data) => Promise<void>
    join: (caller: Caller, data: Data) => Promise<void>
    leave: (caller, data: Data) => Promise<void>
    grant: (caller, data: Data) => Promise<void>
    rescind: (caller, data: Data) => Promise<void>
}

type Caller = {
    uid: number
    ip: string | number | null
}

type Data = {
    name: string
    ownerUid: number
    system: boolean
    slug: string
    uid: number
}

type GroupData = {
    name: string
    slug: string
    createtime: number
    userTitle: string
    userTitleEnabled: number
    description: string
    memberCount: number
    hidden: number
    system: number
    private: number
    disableJoinRequests: number
    disableLeave: number
}

type NotificationData = {
    type: string
    bodyShort: string
    nid: string
    path: string
    from: number
}

type Additional = {
    groupName: string
    targetUid?: string
}

async function isOwner(caller: Caller, groupName: string): Promise<void> {
    if (typeof groupName !== 'string') {
        throw new Error('[[error:invalid-group-name]]');
    }
    const [hasAdminPrivilege, isGlobalModerator, isOwner, group]: [boolean, boolean, boolean, GroupData] =
    await Promise.all([
        privileges.admin.can('admin:groups', caller.uid) as boolean,
        user.isGlobalModerator(caller.uid) as boolean,
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        groups.ownership.isOwner(caller.uid, groupName) as boolean,
        (groups.getGroupData as (groupName: string) => GroupData)(groupName),
    ]);

    const check: boolean = isOwner || hasAdminPrivilege || (isGlobalModerator && !group.system);
    if (!check) {
        throw new Error('[[error:no-privileges]]');
    }
}

function logGroupEvent(caller: Caller, event: string, additional: Additional): void {
    events.log({
        type: event,
        uid: caller.uid,
        ip: caller.ip,
        ...additional,
    })
        .catch((err) => {
            console.error('Error logging group event: ', err);
        });
}

const groupsAPI: GroupsAPI = {
    create: async function (caller: Caller, data: Data): Promise<GroupData> {
        if (!caller.uid) {
            throw new Error('[[error:no-privileges]]');
        } else if (!data) {
            throw new Error('[[error:invalid-data]]');
        } else if (typeof data.name !== 'string' || groups.isPrivilegeGroup(data.name)) {
            throw new Error('[[error:invalid-group-name]]');
        }

        const canCreate: boolean = await privileges.global.can('group:create', caller.uid) as boolean;
        if (!canCreate) {
            throw new Error('[[error:no-privileges]]');
        }
        data.ownerUid = caller.uid;
        data.system = false;

        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const groupData: Promise<GroupData> = await groups.create(data) as Promise<GroupData>;
        logGroupEvent(caller, 'group-create', {
            groupName: data.name,
        });

        return groupData;
    },

    update: async function (caller: Caller, data: Data): Promise<GroupData> {
        if (!data) {
            throw new Error('[[error:invalid-data]]');
        }
        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        await isOwner(caller, groupName);

        delete data.slug;
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.update(groupName, data) as Promise<void>;

        return await (groups.getGroupData as (groupName: string) => Promise<GroupData>)(data.name || groupName);
    },

    delete: async function (caller: Caller, data: Data): Promise<void> {
        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        await isOwner(caller, groupName);
        if (
            groups.systemGroups.includes(groupName) ||
            groups.ephemeralGroups.includes(groupName)
        ) {
            throw new Error('[[error:not-allowed]]');
        }
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.destroy(groupName) as Promise<void>;
        logGroupEvent(caller, 'group-delete', {
            groupName: groupName,
        });
    },

    join: async function (caller: Caller, data: Data): Promise<void> {
        if (!data) {
            throw new Error('[[error:invalid-data]]');
        }

        if (caller.uid <= 0 || !data.uid) {
            throw new Error('[[error:invalid-uid]]');
        }

        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        if (!groupName) {
            throw new Error('[[error:no-group]]');
        }

        const isCallerAdmin: boolean = await user.isAdministrator(caller.uid) as boolean;
        if (!isCallerAdmin && (
            groups.systemGroups.includes(groupName) ||
            groups.isPrivilegeGroup(groupName)
        )) {
            throw new Error('[[error:not-allowed]]');
        }

        const [groupData, isCallerOwner, userExists]: [GroupData, boolean, boolean] = await Promise.all([
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groups.getGroupData(groupName) as GroupData,
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groups.ownership.isOwner(caller.uid, groupName) as boolean,
            user.exists(data.uid) as boolean,
        ]);

        if (!userExists) {
            throw new Error('[[error:invalid-uid]]');
        }

        const isSelf: boolean = parseInt(String(caller.uid), 10) === parseInt(String(data.uid), 10);
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        if (!meta.config.allowPrivateGroups && isSelf) {
            // all groups are public!
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.join(groupName, data.uid) as Promise<void>;
            logGroupEvent(caller, 'group-join', {
                groupName: groupName,
                targetUid: String(data.uid),
            });
            return;
        }

        if (!isCallerAdmin && isSelf && groupData.private && groupData.disableJoinRequests) {
            throw new Error('[[error:group-join-disabled]]');
        }

        if ((!groupData.private && isSelf) || isCallerAdmin || isCallerOwner) {
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.join(groupName, data.uid) as Promise<void>;
            logGroupEvent(caller, 'group-join', {
                groupName: groupName,
                targetUid: String(data.uid),
            });
        } else if (isSelf) {
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.requestMembership(groupName, caller.uid) as Promise<void>;
            logGroupEvent(caller, 'group-request-membership', {
                groupName: groupName,
                targetUid: String(data.uid),
            });
        }
    },

    leave: async function (caller: Caller, data: Data): Promise<void> {
        if (!data) {
            throw new Error('[[error:invalid-data]]');
        }

        if (caller.uid <= 0) {
            throw new Error('[[error:invalid-uid]]');
        }

        const isSelf: boolean = parseInt(String(caller.uid), 10) === parseInt(String(data.uid), 10);
        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        if (!groupName) {
            throw new Error('[[error:no-group]]');
        }

        if (typeof groupName !== 'string') {
            throw new Error('[[error:invalid-group-name]]');
        }

        if (groupName === 'administrators' && isSelf) {
            throw new Error('[[error:cant-remove-self-as-admin]]');
        }

        const [groupData, isCallerAdmin, isCallerOwner, userExists, isMember] = await Promise.all([
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groups.getGroupData(groupName) as GroupData,
            user.isAdministrator(caller.uid) as boolean,
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groups.ownership.isOwner(caller.uid, groupName) as boolean,
            user.exists(data.uid) as boolean,
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groups.isMember(data.uid, groupName) as boolean,
        ]);

        if (!userExists) {
            throw new Error('[[error:invalid-uid]]');
        }
        if (!isMember) {
            return;
        }

        if (groupData.disableLeave && isSelf) {
            throw new Error('[[error:group-leave-disabled]]');
        }

        if (isSelf || isCallerAdmin || isCallerOwner) {
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.leave(groupName, data.uid) as Promise<void>;
        } else {
            throw new Error('[[error:no-privileges]]');
        }

        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const { displayname } : { displayname: string } = await user.getUserFields(data.uid, ['username']) as { displayname: string };

        const notification: NotificationData = await notifications.create({
            type: 'group-leave',
            bodyShort: `[[groups:membership.leave.notification_title, ${displayname}, ${groupName}]]`,
            nid: `group:${validator.escape(groupName)}:uid:${data.uid}:group-leave`,
            path: `/groups/${slugify(groupName) as string}`,
            from: data.uid,
        }) as NotificationData;
        const uids: string[] = await groups.getOwners(groupName) as string[];
        await notifications.push(notification, uids) as Promise<void>;

        logGroupEvent(caller, 'group-leave', {
            groupName: groupName,
            targetUid: String(data.uid),
        });
    },

    grant: async (caller: Caller, data: Data): Promise<void> => {
        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        await isOwner(caller, groupName);

        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.ownership.grant(data.uid, groupName) as Promise<void>;
        logGroupEvent(caller, 'group-owner-grant', {
            groupName: groupName,
            targetUid: String(data.uid),
        });
    },

    rescind: async (caller: Caller, data: Data): Promise<void> => {
        const groupName: string = await groups.getGroupNameByGroupSlug(data.slug) as string;
        await isOwner(caller, groupName);

        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.ownership.rescind(data.uid, groupName) as Promise<void>;
        logGroupEvent(caller, 'group-owner-rescind', {
            groupName: groupName,
            targetUid: String(data.uid),
        });
    },
};

export = groupsAPI;
