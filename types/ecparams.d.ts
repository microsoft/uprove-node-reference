import { Group, GroupElement } from "./math.js";
import { ECGroup } from "./uprove.js";
interface ECGroupParams {
    descGq: ECGroup;
    Gq: Group;
    oid: string;
    g: GroupElement[];
    gt: GroupElement;
}
export declare function getEcGroup(descGq: ECGroup): ECGroupParams;
export {};
