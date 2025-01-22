"use client"

// import { useParams } from "next/navigation";
import Image from "next/image"

import Lucide from 'lucide-react';
import { SidebarItem } from "./sidebar-item";
import { RxExit } from "react-icons/rx";


import LogoWhite from "@/public/Images/logo-white.png"


export const SidebarRoutes = () => {

    // const params = useParams()
    // const id = `${params.storeId}`

    const Routes = [
        {
            icon: "House",
            label: "Home",
            href: `/students`,
        },
        {
            icon: "GraduationCap",
            label: "Grade",
            href: `/students/grade`,
        },
        {
            icon: "Briefcase",
            label: "Assignment",
            href: `/students/assignment`,
        },
        {
            icon: "ChartNoAxesCombined",
            label: "Analytics",
            href: `/students/analytics`,
        },
    ]

    const routes = Routes
    return (
        <div className="relative flex flex-col w-full h-full gap-y-[30px] ">
            <div className=' pl-4 md:pl-[50px] mt-[35px] mb-[15px]'>
                <Image
                    src={LogoWhite}
                    width={135}
                    height={45}
                    alt="logo"
                    className="flex"

                />

            </div>
            <div className="flex flex-col gap-y-2">
                {routes.map((route) => (
                    <SidebarItem
                        key={route.href}
                        icon={route.icon as keyof typeof Lucide.icons}
                        label={route.label}
                        href={route.href}

                    />
                ))}
            </div>

            <button className='flex ml-5 md:ml-[50px] items-center gap-x-3 absolute bottom-[50px] text-white'>
                <RxExit size={20} />
                <p className="font-semibold text-sm md:text-base">Log out</p>
            </button>
        </div>
    )
}