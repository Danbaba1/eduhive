"use client";

import { usePathname, useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import Icon, { IconNames } from "./icon";


interface SidebarItemProps {
    icon: IconNames;
    label: string;
    href: string;
}

export const SidebarItem = ({ icon, label, href }: SidebarItemProps) => {
    const pathname = usePathname();
    const router = useRouter();

    const isActive =
        (pathname === `/students` && href === `/students`) ||
        pathname === href ||
        pathname?.startsWith(`${href}/`);

    const onClick = () => {
        router.push(href);
    };

    return (
        <button
            onClick={onClick}
            type="button"
            className={cn(
                "flex w-full items-center gap-x-2 text-white text-sm md:text-base font-medium  transition-all hover:text-[#F1B53E] hover:bg-slate-300/20 pl-[50px]",
                isActive && "text-[#F1B53E] bg-sky-200/20 hover:bg-sky-200/20 hover:text-[#F1B53E]/70 border-[#F1B53E] border-l-4 md:border-l-6 rounded-md "
            )}
        >

            <div className="flex items-center gap-x-2 py-4">
                <Icon
                    name={icon}
                    size={22}
                    className={cn("text-white", isActive && "text-[#F1B53E]")}
                />
                {label}
            </div>

        </button>
    );
};
