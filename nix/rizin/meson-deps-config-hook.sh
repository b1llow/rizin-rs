# shellcheck shell=bash

mesonDepsConfigHook() {
    if [[ -z ${mesonDeps-} ]]; then
        echo "mesonDepsConfigHook: mesonDeps is not set" >&2
        return 1
    fi

    rm -rf subprojects
    cp -r "$mesonDeps" subprojects
    chmod -R u+w subprojects
}

preConfigureHooks+=(mesonDepsConfigHook)
