import Image from "next/image";
import { Button } from "./ui/button";
import NavbarActions from "./navbar-actions";
import Logo from "../public/Images/logo.png"
import Link from "next/link";

const Navbar = () => {
    return (
        <div className="mt-[10px] w-full  ">
            <div className="flex items-center p-2 justify-between">
                <div>
                    <Image src={Logo}
                        width={133}
                        height={45}
                        alt="logo"
                        className="w-[88px] md:w-[133px] h-[30px] md:h-[45px] "
                    />

                </div>
                <div>
                    <NavbarActions />
                </div>
                <div>
                    <Link href="/sign-up">

                        <Button variant="default" className="bg-[#0F52BA] rounded-[10px] px-8 hover:text-[#0F52BA] hover:bg-white ">
                            <span className="font-semibold text-xl ">
                                Sign up
                            </span>
                        </Button>
                    </Link>
                </div>
            </div>
        </div>
    );
}

export default Navbar;