import { format, tryParse } from "jsr:@std/semver@1";

const args = Deno.args;
if (args.length === 0) {
    console.error(
        "Usage: publish.ts <mod> [--bump] [--patch | -p] [--minor | -m] [--major | -M] [--tag | -t]",
    );
    Deno.exit(1);
}

const dir = import.meta.dirname;
const path = `${dir}/../versions.json`;

const versions = JSON.parse(Deno.readTextFileSync(path));
const mod = args[0];
const bump = args.includes("--bump");
const patch = args.includes("--patch") || args.includes("-p");
const minor = args.includes("--minor") || args.includes("-m");
const major = args.includes("--major") || args.includes("-M");
const tag = args.includes("--tag") || args.includes("-t");
const setValue = args.indexOf("--value");
let value: string | undefined = undefined;
if (setValue > -1) {
    if (setValue + 1 >= args.length) {
        console.error("Usage: publish.ts <mod> --value <new_version>");
        Deno.exit(1);
    }

    value = args[setValue + 1];
}

const ver = versions[mod];
let version = tryParse(ver);
if (version === null) {
    console.error(`Invalid semantic version for module ${mod}: ${ver}`);
    Deno.exit(1);
}

if (bump) {
    if (patch) {
        version!.patch++;
    } else if (minor) {
        version!.minor++;
        version!.patch = 0;
    } else if (major) {
        version!.major++;
        version!.minor = 0;
        version!.patch = 0;
    }
} else {
    if (patch) {
        const next = Number.parseInt(value!);
        if (isNaN(next)) {
            console.error("Invalid value for patch version");
            Deno.exit(1);
        }
        version!.patch = next;
    } else if (minor) {
        const next = Number.parseInt(value!);
        if (isNaN(next)) {
            console.error("Invalid value for minor version");
            Deno.exit(1);
        }
        version!.minor = next;
        version!.patch = 0;
    } else if (major) {
        const next = Number.parseInt(value!);
        if (isNaN(next)) {
            console.error("Invalid value for major version");
            Deno.exit(1);
        }
        version!.major = next;
        version!.minor = 0;
        version!.patch = 0;
    } else if (value) {
        const newVersion = tryParse(value);
        if (newVersion === null) {
            console.error(`Invalid semantic version: ${value}`);
            Deno.exit(1);
        }
        version = newVersion;
    }
}

versions[mod] = format(version!);
Deno.writeTextFileSync(path, JSON.stringify(versions, null, 4));

if (tag) {
    let cmd = new Deno.Command("git", {
        args: ["commit", "-a", "-m", "update module version for " + mod],
        cwd: dir,
        stdout: "inherit",
        stderr: "inherit",
    });

    const result = await cmd.output();
    if (result.code !== 0) {
        console.error(`Failed to tag version for ${mod}`);
        Deno.exit(result.code);
    }

    cmd = new Deno.Command("git", {
        args: [
            "tag",
            "-a",
            `${mod}/v${versions[mod]}`,
            "-m",
            `Release v${versions[mod]}`,
        ],
        cwd: dir,
        stdout: "inherit",
        stderr: "inherit",
    });

    const tagResult = await cmd.output();
    if (tagResult.code !== 0) {
        console.error(`Failed to create tag for ${mod}`);
        Deno.exit(tagResult.code);
    }

    cmd = new Deno.Command("git", {
        args: ["push", "--tags"],
        cwd: dir,
        stdout: "inherit",
        stderr: "inherit",
    });

    const pushResult = await cmd.output();
    if (pushResult.code !== 0) {
        console.error(`Failed to push tags for ${mod}`);
        Deno.exit(pushResult.code);
    }
}
